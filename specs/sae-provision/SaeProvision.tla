------------------------------- MODULE SaeProvision -------------------------------
(***************************************************************************
  PlusCal of the current SaeNode provision saga.

  Record states = client_record_state.record_availability
    NoRecord            no row
    Synchronization     RECORD_SYNCHRONIZATION — pair reserved
    FetchLocked         RECORD_FETCHING_STARTED — lockFetch held
    RecordShared        RECORD_SHARED — both databases hold keys; the origin
                        device has not acked. Same meaning on both SAEs.
                        Incomplete. A stale row is deleted; ON DELETE CASCADE
                        drops shared_key_material. A fresh row is left alone.
    OriginProvisioned   ORIGIN_PROVISIONED — origin device acked. Written on
                        the peer first, then the origin. The peer device is
                        filled only when both rows are OriginProvisioned.

  The reservation window is 5 minutes. It expires Synchronization,
  FetchLocked, and RecordShared. It does not expire OriginProvisioned.

  MarkPeerProvisioned runs only after the origin device ack, and only from
  RecordShared. MarkOriginProvisioned runs only after the peer mark returns.
  A crash between them leaves the peer OriginProvisioned and the origin
  RecordShared. ReportTerminalSuccess runs only when both marks have returned.

  A later origin retry does not delete a fresh RecordShared. A stale one is
  deleted and a new Synchronization is offered to the peer. If the peer
  rejects it, the origin reservation is rolled back. A later peer-device
  visit delivers only when both rows are OriginProvisioned (delete-before-send).
  A fresh RecordShared on the peer is not a delivery. A stale one is reclaimed
  locally and its keys are dropped.

  Do not treat leftover-share absence as always true: an unreachable peer or
  origin, or a skipped later attempt, leaves the rows. Expiring a reservation
  does not by itself re-run the attempt.

  At every saga label the model may crash the origin JVM or the peer JVM
  (freeze metadata, no compensating delete) before the step commits.
 ***************************************************************************)
EXTENDS Naturals, TLC

NoRecord            == "NoRecord"
Synchronization     == "Synchronization"
FetchLocked         == "FetchLocked"
RecordShared        == "RecordShared"
OriginProvisioned   == "OriginProvisioned"

RecordStates == {NoRecord, Synchronization, FetchLocked, RecordShared, OriginProvisioned}
Incomplete == {Synchronization, FetchLocked, RecordShared}

\* Same issuer may refresh Synchronization. FetchLocked and RecordShared yield
\* only when the reservation window has expired. OriginProvisioned never does.
OriginStartsSync(record, expired) ==
  \/ record = NoRecord
  \/ record = Synchronization
  \/ (record \in {FetchLocked, RecordShared} /\ expired)

\* Peer synchronize accepts a new reservation. A fresh RecordShared or
\* FetchLocked, or an OriginProvisioned row, refuses it.
PeerAcceptsNewSync(record, expired) ==
  \/ record = NoRecord
  \/ record = Synchronization
  \/ (record \in {FetchLocked, RecordShared} /\ expired)

(*--algorithm SaeProvision
variables
  originRecord = NoRecord,
  originReservationExpired = FALSE,
  originHasShare = FALSE,
  peerRecord = NoRecord,
  peerReservationExpired = FALSE,
  peerHasKeyMaterial = FALSE,
  originProcessDied = FALSE,
  peerProcessDied = FALSE,
  fiveMinutesElapsed = FALSE,
  originSaeReachable = TRUE,
  peerSaeReachable = TRUE,
  laterAttemptKind = "none",
  originDeviceHasKeys = FALSE,
  peerDeviceHasKeys = FALSE,
  terminalReportedSuccess = FALSE;

begin
  ReserveOriginPair:
    either
      originRecord := Synchronization || originReservationExpired := FALSE;
    or
      originProcessDied := TRUE;
      goto ElapseReservationTimeout;
    or
      peerProcessDied := TRUE;
      goto ElapseReservationTimeout;
    end either;
  ReservePeerPair:
    either
      peerRecord := Synchronization || peerReservationExpired := FALSE;
    or
      originProcessDied := TRUE;
      goto ElapseReservationTimeout;
    or
      peerProcessDied := TRUE;
      goto ElapseReservationTimeout;
    end either;
  LockOriginFetch:
    either
      originRecord := FetchLocked || originReservationExpired := FALSE;
    or
      originProcessDied := TRUE;
      goto ElapseReservationTimeout;
    or
      peerProcessDied := TRUE;
      goto ElapseReservationTimeout;
    end either;
  LockPeerFetch:
    either
      peerRecord := FetchLocked || peerReservationExpired := FALSE;
    or
      originProcessDied := TRUE;
      goto ElapseReservationTimeout;
    or
      peerProcessDied := TRUE;
      goto ElapseReservationTimeout;
    end either;
  StorePeerKeyMaterial:
    either
      peerHasKeyMaterial := TRUE;
    or
      originProcessDied := TRUE;
      goto ElapseReservationTimeout;
    or
      peerProcessDied := TRUE;
      goto ElapseReservationTimeout;
    end either;
  CommitPeerShare:
    either
      peerRecord := RecordShared || peerReservationExpired := FALSE;
    or
      originProcessDied := TRUE;
      goto ElapseReservationTimeout;
    or
      peerProcessDied := TRUE;
      goto ElapseReservationTimeout;
    end either;
  CommitOriginShare:
    either
      originRecord := RecordShared || originReservationExpired := FALSE || originHasShare := TRUE;
    or
      originProcessDied := TRUE;
      goto ElapseReservationTimeout;
    or
      peerProcessDied := TRUE;
      goto ElapseReservationTimeout;
    end either;
  SendToOriginDevice:
    either
      originDeviceHasKeys := TRUE;
    or
      originProcessDied := TRUE;
      goto ElapseReservationTimeout;
    or
      peerProcessDied := TRUE;
      goto ElapseReservationTimeout;
    end either;
  \* Peer first. A failed or crashed mark leaves both rows RecordShared.
  MarkPeerProvisioned:
    either
      if originDeviceHasKeys /\ peerRecord = RecordShared then
        peerRecord := OriginProvisioned || peerReservationExpired := FALSE;
      end if;
    or
      originProcessDied := TRUE;
      goto ElapseReservationTimeout;
    or
      peerProcessDied := TRUE;
      goto ElapseReservationTimeout;
    end either;
  \* Origin only after the peer row is OriginProvisioned.
  MarkOriginProvisioned:
    either
      if originDeviceHasKeys /\ originRecord = RecordShared /\ peerRecord = OriginProvisioned then
        originRecord := OriginProvisioned || originReservationExpired := FALSE;
      end if;
    or
      originProcessDied := TRUE;
      goto ElapseReservationTimeout;
    or
      peerProcessDied := TRUE;
      goto ElapseReservationTimeout;
    end either;
  ReportTerminalSuccess:
    either
      if originRecord = OriginProvisioned /\ peerRecord = OriginProvisioned
         /\ originDeviceHasKeys /\ originHasShare /\ peerHasKeyMaterial then
        terminalReportedSuccess := TRUE;
      end if;
    or
      \* Origin died after both marks returned, before the terminal line.
      originProcessDied := TRUE;
    or
      peerProcessDied := TRUE;
    end either;
  ElapseReservationTimeout:
    either
      fiveMinutesElapsed := TRUE
      || originReservationExpired := IF originRecord \in Incomplete THEN TRUE ELSE originReservationExpired
      || peerReservationExpired := IF peerRecord \in Incomplete THEN TRUE ELSE peerReservationExpired;
    or
      skip;
    end either;
  MaybeLoseOriginLink:
    either
      originSaeReachable := FALSE;
    or
      skip;
    end either;
  MaybeLosePeerLink:
    either
      peerSaeReachable := FALSE;
    or
      skip;
    end either;
  LaterAttempt:
    either
      \* Origin retries. Fresh RecordShared and fresh FetchLocked wait.
      \* Stale incomplete state, a Synchronization row, or no row starts a
      \* new reservation. The peer must accept it; otherwise the origin
      \* reservation is rolled back. Peer down rolls the origin back only.
      if originRecord = OriginProvisioned
         \/ (originRecord = FetchLocked /\ ~originReservationExpired)
         \/ (originRecord = RecordShared /\ ~originReservationExpired) then
        laterAttemptKind := "origin";
      elsif ~peerSaeReachable then
        originRecord := NoRecord || originReservationExpired := FALSE || originHasShare := FALSE
        || laterAttemptKind := "origin";
      elsif PeerAcceptsNewSync(peerRecord, peerReservationExpired) then
        originRecord := Synchronization || originReservationExpired := FALSE || originHasShare := FALSE
        || peerRecord := Synchronization || peerReservationExpired := FALSE || peerHasKeyMaterial := FALSE
        || laterAttemptKind := "origin";
      else
        originRecord := NoRecord || originReservationExpired := FALSE || originHasShare := FALSE
        || laterAttemptKind := "origin";
      end if;
    or
      \* Peer device. RecordShared is not deliverable. Stale incomplete state
      \* is reclaimed locally and its keys are dropped. Delivery requires both
      \* rows OriginProvisioned, then delete-before-send.
      if peerRecord = RecordShared /\ ~peerReservationExpired then
        laterAttemptKind := "peer";
      elsif peerRecord \in Incomplete /\ peerReservationExpired then
        peerRecord := Synchronization || peerReservationExpired := FALSE || peerHasKeyMaterial := FALSE
        || laterAttemptKind := "peer";
      elsif peerRecord = OriginProvisioned then
        if originSaeReachable = FALSE then
          laterAttemptKind := "peer";
        elsif originRecord = OriginProvisioned then
          either
            originRecord := NoRecord || originReservationExpired := FALSE || originHasShare := FALSE
            || peerRecord := NoRecord || peerReservationExpired := FALSE || peerHasKeyMaterial := FALSE
            || peerDeviceHasKeys := TRUE
            || laterAttemptKind := "peer";
          or
            originRecord := NoRecord || originReservationExpired := FALSE || originHasShare := FALSE
            || peerRecord := NoRecord || peerReservationExpired := FALSE || peerHasKeyMaterial := FALSE
            || laterAttemptKind := "peer";
          end either;
        elsif originRecord \in Incomplete /\ ~originReservationExpired then
          laterAttemptKind := "peer";
        else
          originRecord := NoRecord || originReservationExpired := FALSE || originHasShare := FALSE
          || peerRecord := NoRecord || peerReservationExpired := FALSE || peerHasKeyMaterial := FALSE
          || laterAttemptKind := "peer";
        end if;
      else
        laterAttemptKind := "peer";
      end if;
    or
      skip;
    end either;
end algorithm; *)
\* BEGIN TRANSLATION
VARIABLES pc, originRecord, originReservationExpired, originHasShare, 
          peerRecord, peerReservationExpired, peerHasKeyMaterial, 
          originProcessDied, peerProcessDied, fiveMinutesElapsed, 
          originSaeReachable, peerSaeReachable, laterAttemptKind, 
          originDeviceHasKeys, peerDeviceHasKeys, terminalReportedSuccess

vars == << pc, originRecord, originReservationExpired, originHasShare, 
           peerRecord, peerReservationExpired, peerHasKeyMaterial, 
           originProcessDied, peerProcessDied, fiveMinutesElapsed, 
           originSaeReachable, peerSaeReachable, laterAttemptKind, 
           originDeviceHasKeys, peerDeviceHasKeys, terminalReportedSuccess >>

Init == (* Global variables *)
        /\ originRecord = NoRecord
        /\ originReservationExpired = FALSE
        /\ originHasShare = FALSE
        /\ peerRecord = NoRecord
        /\ peerReservationExpired = FALSE
        /\ peerHasKeyMaterial = FALSE
        /\ originProcessDied = FALSE
        /\ peerProcessDied = FALSE
        /\ fiveMinutesElapsed = FALSE
        /\ originSaeReachable = TRUE
        /\ peerSaeReachable = TRUE
        /\ laterAttemptKind = "none"
        /\ originDeviceHasKeys = FALSE
        /\ peerDeviceHasKeys = FALSE
        /\ terminalReportedSuccess = FALSE
        /\ pc = "ReserveOriginPair"

ReserveOriginPair == /\ pc = "ReserveOriginPair"
                     /\ \/ /\ /\ originRecord' = Synchronization
                              /\ originReservationExpired' = FALSE
                           /\ pc' = "ReservePeerPair"
                           /\ UNCHANGED <<originProcessDied, peerProcessDied>>
                        \/ /\ originProcessDied' = TRUE
                           /\ pc' = "ElapseReservationTimeout"
                           /\ UNCHANGED <<originRecord, originReservationExpired, peerProcessDied>>
                        \/ /\ peerProcessDied' = TRUE
                           /\ pc' = "ElapseReservationTimeout"
                           /\ UNCHANGED <<originRecord, originReservationExpired, originProcessDied>>
                     /\ UNCHANGED << originHasShare, peerRecord, 
                                     peerReservationExpired, 
                                     peerHasKeyMaterial, fiveMinutesElapsed, 
                                     originSaeReachable, peerSaeReachable, 
                                     laterAttemptKind, originDeviceHasKeys, 
                                     peerDeviceHasKeys, 
                                     terminalReportedSuccess >>

ReservePeerPair == /\ pc = "ReservePeerPair"
                   /\ \/ /\ /\ peerRecord' = Synchronization
                            /\ peerReservationExpired' = FALSE
                         /\ pc' = "LockOriginFetch"
                         /\ UNCHANGED <<originProcessDied, peerProcessDied>>
                      \/ /\ originProcessDied' = TRUE
                         /\ pc' = "ElapseReservationTimeout"
                         /\ UNCHANGED <<peerRecord, peerReservationExpired, peerProcessDied>>
                      \/ /\ peerProcessDied' = TRUE
                         /\ pc' = "ElapseReservationTimeout"
                         /\ UNCHANGED <<peerRecord, peerReservationExpired, originProcessDied>>
                   /\ UNCHANGED << originRecord, originReservationExpired, 
                                   originHasShare, peerHasKeyMaterial, 
                                   fiveMinutesElapsed, originSaeReachable, 
                                   peerSaeReachable, laterAttemptKind, 
                                   originDeviceHasKeys, peerDeviceHasKeys, 
                                   terminalReportedSuccess >>

LockOriginFetch == /\ pc = "LockOriginFetch"
                   /\ \/ /\ /\ originRecord' = FetchLocked
                            /\ originReservationExpired' = FALSE
                         /\ pc' = "LockPeerFetch"
                         /\ UNCHANGED <<originProcessDied, peerProcessDied>>
                      \/ /\ originProcessDied' = TRUE
                         /\ pc' = "ElapseReservationTimeout"
                         /\ UNCHANGED <<originRecord, originReservationExpired, peerProcessDied>>
                      \/ /\ peerProcessDied' = TRUE
                         /\ pc' = "ElapseReservationTimeout"
                         /\ UNCHANGED <<originRecord, originReservationExpired, originProcessDied>>
                   /\ UNCHANGED << originHasShare, peerRecord, 
                                   peerReservationExpired, peerHasKeyMaterial, 
                                   fiveMinutesElapsed, originSaeReachable, 
                                   peerSaeReachable, laterAttemptKind, 
                                   originDeviceHasKeys, peerDeviceHasKeys, 
                                   terminalReportedSuccess >>

LockPeerFetch == /\ pc = "LockPeerFetch"
                 /\ \/ /\ /\ peerRecord' = FetchLocked
                          /\ peerReservationExpired' = FALSE
                       /\ pc' = "StorePeerKeyMaterial"
                       /\ UNCHANGED <<originProcessDied, peerProcessDied>>
                    \/ /\ originProcessDied' = TRUE
                       /\ pc' = "ElapseReservationTimeout"
                       /\ UNCHANGED <<peerRecord, peerReservationExpired, peerProcessDied>>
                    \/ /\ peerProcessDied' = TRUE
                       /\ pc' = "ElapseReservationTimeout"
                       /\ UNCHANGED <<peerRecord, peerReservationExpired, originProcessDied>>
                 /\ UNCHANGED << originRecord, originReservationExpired, 
                                 originHasShare, peerHasKeyMaterial, 
                                 fiveMinutesElapsed, originSaeReachable, 
                                 peerSaeReachable, laterAttemptKind, 
                                 originDeviceHasKeys, peerDeviceHasKeys, 
                                 terminalReportedSuccess >>

StorePeerKeyMaterial == /\ pc = "StorePeerKeyMaterial"
                        /\ \/ /\ peerHasKeyMaterial' = TRUE
                              /\ pc' = "CommitPeerShare"
                              /\ UNCHANGED <<originProcessDied, peerProcessDied>>
                           \/ /\ originProcessDied' = TRUE
                              /\ pc' = "ElapseReservationTimeout"
                              /\ UNCHANGED <<peerHasKeyMaterial, peerProcessDied>>
                           \/ /\ peerProcessDied' = TRUE
                              /\ pc' = "ElapseReservationTimeout"
                              /\ UNCHANGED <<peerHasKeyMaterial, originProcessDied>>
                        /\ UNCHANGED << originRecord, originReservationExpired, 
                                        originHasShare, peerRecord, 
                                        peerReservationExpired, 
                                        fiveMinutesElapsed, originSaeReachable, 
                                        peerSaeReachable, laterAttemptKind, 
                                        originDeviceHasKeys, peerDeviceHasKeys, 
                                        terminalReportedSuccess >>

CommitPeerShare == /\ pc = "CommitPeerShare"
                   /\ \/ /\ /\ peerRecord' = RecordShared
                            /\ peerReservationExpired' = FALSE
                         /\ pc' = "CommitOriginShare"
                         /\ UNCHANGED <<originProcessDied, peerProcessDied>>
                      \/ /\ originProcessDied' = TRUE
                         /\ pc' = "ElapseReservationTimeout"
                         /\ UNCHANGED <<peerRecord, peerReservationExpired, peerProcessDied>>
                      \/ /\ peerProcessDied' = TRUE
                         /\ pc' = "ElapseReservationTimeout"
                         /\ UNCHANGED <<peerRecord, peerReservationExpired, originProcessDied>>
                   /\ UNCHANGED << originRecord, originReservationExpired, 
                                   originHasShare, peerHasKeyMaterial, 
                                   fiveMinutesElapsed, originSaeReachable, 
                                   peerSaeReachable, laterAttemptKind, 
                                   originDeviceHasKeys, peerDeviceHasKeys, 
                                   terminalReportedSuccess >>

CommitOriginShare == /\ pc = "CommitOriginShare"
                     /\ \/ /\ /\ originHasShare' = TRUE
                              /\ originRecord' = RecordShared
                              /\ originReservationExpired' = FALSE
                           /\ pc' = "SendToOriginDevice"
                           /\ UNCHANGED <<originProcessDied, peerProcessDied>>
                        \/ /\ originProcessDied' = TRUE
                           /\ pc' = "ElapseReservationTimeout"
                           /\ UNCHANGED <<originRecord, originReservationExpired, originHasShare, peerProcessDied>>
                        \/ /\ peerProcessDied' = TRUE
                           /\ pc' = "ElapseReservationTimeout"
                           /\ UNCHANGED <<originRecord, originReservationExpired, originHasShare, originProcessDied>>
                     /\ UNCHANGED << peerRecord, peerReservationExpired, 
                                     peerHasKeyMaterial, fiveMinutesElapsed, 
                                     originSaeReachable, peerSaeReachable, 
                                     laterAttemptKind, originDeviceHasKeys, 
                                     peerDeviceHasKeys, 
                                     terminalReportedSuccess >>

SendToOriginDevice == /\ pc = "SendToOriginDevice"
                      /\ \/ /\ originDeviceHasKeys' = TRUE
                            /\ pc' = "MarkPeerProvisioned"
                            /\ UNCHANGED <<originProcessDied, peerProcessDied>>
                         \/ /\ originProcessDied' = TRUE
                            /\ pc' = "ElapseReservationTimeout"
                            /\ UNCHANGED <<peerProcessDied, originDeviceHasKeys>>
                         \/ /\ peerProcessDied' = TRUE
                            /\ pc' = "ElapseReservationTimeout"
                            /\ UNCHANGED <<originProcessDied, originDeviceHasKeys>>
                      /\ UNCHANGED << originRecord, originReservationExpired, 
                                      originHasShare, peerRecord, 
                                      peerReservationExpired, 
                                      peerHasKeyMaterial, fiveMinutesElapsed, 
                                      originSaeReachable, peerSaeReachable, 
                                      laterAttemptKind, peerDeviceHasKeys, 
                                      terminalReportedSuccess >>

MarkPeerProvisioned == /\ pc = "MarkPeerProvisioned"
                       /\ \/ /\ IF originDeviceHasKeys /\ peerRecord = RecordShared
                                   THEN /\ /\ peerRecord' = OriginProvisioned
                                           /\ peerReservationExpired' = FALSE
                                   ELSE /\ TRUE
                                        /\ UNCHANGED << peerRecord, 
                                                        peerReservationExpired >>
                             /\ pc' = "MarkOriginProvisioned"
                             /\ UNCHANGED <<originProcessDied, peerProcessDied>>
                          \/ /\ originProcessDied' = TRUE
                             /\ pc' = "ElapseReservationTimeout"
                             /\ UNCHANGED <<peerRecord, peerReservationExpired, peerProcessDied>>
                          \/ /\ peerProcessDied' = TRUE
                             /\ pc' = "ElapseReservationTimeout"
                             /\ UNCHANGED <<peerRecord, peerReservationExpired, originProcessDied>>
                       /\ UNCHANGED << originRecord, originReservationExpired, 
                                       originHasShare, peerHasKeyMaterial, 
                                       fiveMinutesElapsed, originSaeReachable, 
                                       peerSaeReachable, laterAttemptKind, 
                                       originDeviceHasKeys, peerDeviceHasKeys, 
                                       terminalReportedSuccess >>

MarkOriginProvisioned == /\ pc = "MarkOriginProvisioned"
                         /\ \/ /\ IF originDeviceHasKeys /\ originRecord = RecordShared /\ peerRecord = OriginProvisioned
                                     THEN /\ /\ originRecord' = OriginProvisioned
                                             /\ originReservationExpired' = FALSE
                                     ELSE /\ TRUE
                                          /\ UNCHANGED << originRecord, 
                                                          originReservationExpired >>
                               /\ pc' = "ReportTerminalSuccess"
                               /\ UNCHANGED <<originProcessDied, peerProcessDied>>
                            \/ /\ originProcessDied' = TRUE
                               /\ pc' = "ElapseReservationTimeout"
                               /\ UNCHANGED <<originRecord, originReservationExpired, peerProcessDied>>
                            \/ /\ peerProcessDied' = TRUE
                               /\ pc' = "ElapseReservationTimeout"
                               /\ UNCHANGED <<originRecord, originReservationExpired, originProcessDied>>
                         /\ UNCHANGED << originHasShare, peerRecord, 
                                         peerReservationExpired, 
                                         peerHasKeyMaterial, 
                                         fiveMinutesElapsed, 
                                         originSaeReachable, peerSaeReachable, 
                                         laterAttemptKind, originDeviceHasKeys, 
                                         peerDeviceHasKeys, 
                                         terminalReportedSuccess >>

ReportTerminalSuccess == /\ pc = "ReportTerminalSuccess"
                         /\ \/ /\ IF originRecord = OriginProvisioned /\ peerRecord = OriginProvisioned
                                     /\ originDeviceHasKeys /\ originHasShare /\ peerHasKeyMaterial
                                     THEN /\ terminalReportedSuccess' = TRUE
                                     ELSE /\ TRUE
                                          /\ UNCHANGED terminalReportedSuccess
                               /\ UNCHANGED <<originProcessDied, peerProcessDied>>
                            \/ /\ originProcessDied' = TRUE
                               /\ UNCHANGED <<peerProcessDied, terminalReportedSuccess>>
                            \/ /\ peerProcessDied' = TRUE
                               /\ UNCHANGED <<originProcessDied, terminalReportedSuccess>>
                         /\ pc' = "ElapseReservationTimeout"
                         /\ UNCHANGED << originRecord, 
                                         originReservationExpired, 
                                         originHasShare, peerRecord, 
                                         peerReservationExpired, 
                                         peerHasKeyMaterial, 
                                         fiveMinutesElapsed, 
                                         originSaeReachable, peerSaeReachable, 
                                         laterAttemptKind, originDeviceHasKeys, 
                                         peerDeviceHasKeys >>

ElapseReservationTimeout == /\ pc = "ElapseReservationTimeout"
                            /\ \/ /\ /\ fiveMinutesElapsed' = TRUE
                                     /\ originReservationExpired' = (IF originRecord \in Incomplete THEN TRUE ELSE originReservationExpired)
                                     /\ peerReservationExpired' = (IF peerRecord \in Incomplete THEN TRUE ELSE peerReservationExpired)
                               \/ /\ TRUE
                                  /\ UNCHANGED <<originReservationExpired, peerReservationExpired, fiveMinutesElapsed>>
                            /\ pc' = "MaybeLoseOriginLink"
                            /\ UNCHANGED << originRecord, originHasShare, 
                                            peerRecord, peerHasKeyMaterial, 
                                            originProcessDied, peerProcessDied, 
                                            originSaeReachable, 
                                            peerSaeReachable, laterAttemptKind, 
                                            originDeviceHasKeys, 
                                            peerDeviceHasKeys, 
                                            terminalReportedSuccess >>

MaybeLoseOriginLink == /\ pc = "MaybeLoseOriginLink"
                       /\ \/ /\ originSaeReachable' = FALSE
                          \/ /\ TRUE
                             /\ UNCHANGED originSaeReachable
                       /\ pc' = "MaybeLosePeerLink"
                       /\ UNCHANGED << originRecord, originReservationExpired, 
                                       originHasShare, peerRecord, 
                                       peerReservationExpired, 
                                       peerHasKeyMaterial, originProcessDied, 
                                       peerProcessDied, fiveMinutesElapsed, 
                                       peerSaeReachable, laterAttemptKind, 
                                       originDeviceHasKeys, peerDeviceHasKeys, 
                                       terminalReportedSuccess >>

MaybeLosePeerLink == /\ pc = "MaybeLosePeerLink"
                     /\ \/ /\ peerSaeReachable' = FALSE
                        \/ /\ TRUE
                           /\ UNCHANGED peerSaeReachable
                     /\ pc' = "LaterAttempt"
                     /\ UNCHANGED << originRecord, originReservationExpired, 
                                     originHasShare, peerRecord, 
                                     peerReservationExpired, 
                                     peerHasKeyMaterial, originProcessDied, 
                                     peerProcessDied, fiveMinutesElapsed, 
                                     originSaeReachable, laterAttemptKind, 
                                     originDeviceHasKeys, peerDeviceHasKeys, 
                                     terminalReportedSuccess >>

LaterAttempt == /\ pc = "LaterAttempt"
                /\ \/ /\ IF originRecord = OriginProvisioned
                            \/ (originRecord = FetchLocked /\ ~originReservationExpired)
                            \/ (originRecord = RecordShared /\ ~originReservationExpired)
                            THEN /\ laterAttemptKind' = "origin"
                                 /\ UNCHANGED << originRecord, 
                                                 originReservationExpired, 
                                                 originHasShare, peerRecord, 
                                                 peerReservationExpired, 
                                                 peerHasKeyMaterial >>
                            ELSE /\ IF ~peerSaeReachable
                                       THEN /\ /\ laterAttemptKind' = "origin"
                                               /\ originHasShare' = FALSE
                                               /\ originRecord' = NoRecord
                                               /\ originReservationExpired' = FALSE
                                            /\ UNCHANGED << peerRecord, 
                                                            peerReservationExpired, 
                                                            peerHasKeyMaterial >>
                                       ELSE /\ IF PeerAcceptsNewSync(peerRecord, peerReservationExpired)
                                                  THEN /\ /\ laterAttemptKind' = "origin"
                                                          /\ originHasShare' = FALSE
                                                          /\ originRecord' = Synchronization
                                                          /\ originReservationExpired' = FALSE
                                                          /\ peerHasKeyMaterial' = FALSE
                                                          /\ peerRecord' = Synchronization
                                                          /\ peerReservationExpired' = FALSE
                                                  ELSE /\ /\ laterAttemptKind' = "origin"
                                                          /\ originHasShare' = FALSE
                                                          /\ originRecord' = NoRecord
                                                          /\ originReservationExpired' = FALSE
                                                       /\ UNCHANGED << peerRecord, 
                                                                       peerReservationExpired, 
                                                                       peerHasKeyMaterial >>
                      /\ UNCHANGED peerDeviceHasKeys
                   \/ /\ IF peerRecord = RecordShared /\ ~peerReservationExpired
                            THEN /\ laterAttemptKind' = "peer"
                                 /\ UNCHANGED << originRecord, 
                                                 originReservationExpired, 
                                                 originHasShare, peerRecord, 
                                                 peerReservationExpired, 
                                                 peerHasKeyMaterial, 
                                                 peerDeviceHasKeys >>
                            ELSE /\ IF peerRecord \in Incomplete /\ peerReservationExpired
                                       THEN /\ /\ laterAttemptKind' = "peer"
                                               /\ peerHasKeyMaterial' = FALSE
                                               /\ peerRecord' = Synchronization
                                               /\ peerReservationExpired' = FALSE
                                            /\ UNCHANGED << originRecord, 
                                                            originReservationExpired, 
                                                            originHasShare, 
                                                            peerDeviceHasKeys >>
                                       ELSE /\ IF peerRecord = OriginProvisioned
                                                  THEN /\ IF originSaeReachable = FALSE
                                                             THEN /\ laterAttemptKind' = "peer"
                                                                  /\ UNCHANGED << originRecord, 
                                                                                  originReservationExpired, 
                                                                                  originHasShare, 
                                                                                  peerRecord, 
                                                                                  peerReservationExpired, 
                                                                                  peerHasKeyMaterial, 
                                                                                  peerDeviceHasKeys >>
                                                             ELSE /\ IF originRecord = OriginProvisioned
                                                                        THEN /\ \/ /\ /\ laterAttemptKind' = "peer"
                                                                                      /\ originHasShare' = FALSE
                                                                                      /\ originRecord' = NoRecord
                                                                                      /\ originReservationExpired' = FALSE
                                                                                      /\ peerDeviceHasKeys' = TRUE
                                                                                      /\ peerHasKeyMaterial' = FALSE
                                                                                      /\ peerRecord' = NoRecord
                                                                                      /\ peerReservationExpired' = FALSE
                                                                                \/ /\ /\ laterAttemptKind' = "peer"
                                                                                      /\ originHasShare' = FALSE
                                                                                      /\ originRecord' = NoRecord
                                                                                      /\ originReservationExpired' = FALSE
                                                                                      /\ peerHasKeyMaterial' = FALSE
                                                                                      /\ peerRecord' = NoRecord
                                                                                      /\ peerReservationExpired' = FALSE
                                                                                   /\ UNCHANGED peerDeviceHasKeys
                                                                        ELSE /\ IF originRecord \in Incomplete /\ ~originReservationExpired
                                                                                   THEN /\ laterAttemptKind' = "peer"
                                                                                        /\ UNCHANGED << originRecord, 
                                                                                                        originReservationExpired, 
                                                                                                        originHasShare, 
                                                                                                        peerRecord, 
                                                                                                        peerReservationExpired, 
                                                                                                        peerHasKeyMaterial >>
                                                                                   ELSE /\ /\ laterAttemptKind' = "peer"
                                                                                           /\ originHasShare' = FALSE
                                                                                           /\ originRecord' = NoRecord
                                                                                           /\ originReservationExpired' = FALSE
                                                                                           /\ peerHasKeyMaterial' = FALSE
                                                                                           /\ peerRecord' = NoRecord
                                                                                           /\ peerReservationExpired' = FALSE
                                                                             /\ UNCHANGED peerDeviceHasKeys
                                                  ELSE /\ laterAttemptKind' = "peer"
                                                       /\ UNCHANGED << originRecord, 
                                                                       originReservationExpired, 
                                                                       originHasShare, 
                                                                       peerRecord, 
                                                                       peerReservationExpired, 
                                                                       peerHasKeyMaterial, 
                                                                       peerDeviceHasKeys >>
                   \/ /\ TRUE
                      /\ UNCHANGED <<originRecord, originReservationExpired, originHasShare, peerRecord, peerReservationExpired, peerHasKeyMaterial, laterAttemptKind, peerDeviceHasKeys>>
                /\ pc' = "Done"
                /\ UNCHANGED << originProcessDied, peerProcessDied, 
                                fiveMinutesElapsed, originSaeReachable, 
                                peerSaeReachable, originDeviceHasKeys, 
                                terminalReportedSuccess >>

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == pc = "Done" /\ UNCHANGED vars

Next == ReserveOriginPair \/ ReservePeerPair \/ LockOriginFetch
           \/ LockPeerFetch \/ StorePeerKeyMaterial \/ CommitPeerShare
           \/ CommitOriginShare \/ SendToOriginDevice \/ MarkPeerProvisioned
           \/ MarkOriginProvisioned \/ ReportTerminalSuccess
           \/ ElapseReservationTimeout \/ MaybeLoseOriginLink
           \/ MaybeLosePeerLink \/ LaterAttempt
           \/ Terminating

Spec == Init /\ [][Next]_vars

Termination == <>(pc = "Done")

\* END TRANSLATION

TypeOK ==
  /\ originRecord \in RecordStates
  /\ peerRecord \in RecordStates
  /\ originReservationExpired \in BOOLEAN
  /\ peerReservationExpired \in BOOLEAN
  /\ originProcessDied \in BOOLEAN
  /\ peerProcessDied \in BOOLEAN
  /\ fiveMinutesElapsed \in BOOLEAN
  /\ originSaeReachable \in BOOLEAN
  /\ peerSaeReachable \in BOOLEAN
  /\ laterAttemptKind \in {"none", "origin", "peer"}
  /\ originDeviceHasKeys \in BOOLEAN
  /\ peerDeviceHasKeys \in BOOLEAN
  /\ terminalReportedSuccess \in BOOLEAN
  /\ originHasShare \in BOOLEAN
  /\ peerHasKeyMaterial \in BOOLEAN

MatchingSharesWhenCommitted ==
  (originRecord \in {RecordShared, OriginProvisioned}
    /\ peerRecord \in {RecordShared, OriginProvisioned})
    => originHasShare = peerHasKeyMaterial

\* Mark writes the origin only after the peer is already OriginProvisioned.
OriginProvisionedImpliesPeerProvisioned ==
  (originRecord = OriginProvisioned) => peerRecord = OriginProvisioned

ProvisionedMeansOriginDeviceHasKeys ==
  (originRecord = OriginProvisioned \/ peerRecord = OriginProvisioned) => originDeviceHasKeys

PeerDeviceImpliesOriginAlreadyFilled == peerDeviceHasKeys => originDeviceHasKeys

PeerDeviceImpliesShareConsumed == peerDeviceHasKeys => peerRecord = NoRecord /\ originRecord = NoRecord

\* Printed only after both marks return. A later peer delivery may consume both rows.
TerminalSuccessMeansConsistentShare ==
  terminalReportedSuccess =>
    /\ originDeviceHasKeys
    /\ \/ /\ originRecord = OriginProvisioned
          /\ peerRecord = OriginProvisioned
          /\ originHasShare
          /\ peerHasKeyMaterial
       \/ /\ originRecord = NoRecord
          /\ peerRecord = NoRecord
          /\ originHasShare = FALSE
          /\ peerHasKeyMaterial = FALSE

\* Origin retry with the peer up does not leave a stale RecordShared on the origin.
NoStaleOriginSharedAfterOriginRetry ==
  (pc = "Done" /\ fiveMinutesElapsed /\ peerSaeReachable /\ laterAttemptKind = "origin") =>
    ~(originRecord = RecordShared /\ originReservationExpired)

\* Peer visit does not leave its own stale RecordShared. If the peer row is
\* OriginProvisioned and the origin could be read, a stale or missing origin
\* share has been deleted.
NoStaleSharedAfterPeerCheck ==
  (pc = "Done" /\ fiveMinutesElapsed /\ originSaeReachable /\ laterAttemptKind = "peer") =>
    /\ ~(peerRecord = RecordShared /\ peerReservationExpired)
    /\ (peerRecord = OriginProvisioned =>
          originRecord = OriginProvisioned
          \/ (originRecord \in Incomplete /\ ~originReservationExpired))

=============================================================================
