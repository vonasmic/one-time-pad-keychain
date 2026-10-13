------------------------------- MODULE SaeProvision -------------------------------
(***************************************************************************
  PlusCal of the current SaeNode provision saga.

  Record states = client_record_state.record_availability
    NoRecord            no row
    Synchronization     RECORD_SYNCHRONIZATION — pair reserved
    FetchLocked         RECORD_FETCHING_STARTED — lockFetch held
    ShareCommitted      RECORD_AVAILABLE — share committed; origin fill did
                        not finish. Origin deletes this leftover and starts
                        a new share with no operator prompt.
    OriginProvisioned   RECORD_PROVISIONED — origin device acked (origin SAE only)

  OriginShareCheck after a successful origin read:
    OriginProvisioned                      keep; peer device may be filled
    ShareCommitted/FetchLocked, not expired keep; do not fill
    Synchronization, not expired           delete peer only
    missing or expired non-Provisioned     delete both
  Failed origin read: neither delete nor fill. Java has no sweeper.

  ReportTerminalSuccess runs only after MarkOriginProvisioned returns.
  The terminal line is set only for a consistent share: origin device has
  keys, origin row is OriginProvisioned, peer row is ShareCommitted, and
  the material flags match. A crash before that return does not report it.

  Do not treat leftover-share absence as always true: an unreachable origin
  leaves leftover ShareCommitted; expiring a reservation after a later
  attempt does not re-run that attempt.
 ***************************************************************************)
EXTENDS Naturals, TLC

NoRecord            == "NoRecord"
Synchronization     == "Synchronization"
FetchLocked         == "FetchLocked"
ShareCommitted      == "ShareCommitted"
OriginProvisioned   == "OriginProvisioned"

RecordStates == {NoRecord, Synchronization, FetchLocked, ShareCommitted, OriginProvisioned}

(*--algorithm SaeProvision
variables
  originRecord = NoRecord,
  originReservationExpired = FALSE,
  originHasShare = FALSE,
  peerRecord = NoRecord,
  peerReservationExpired = FALSE,
  peerHasKeyMaterial = FALSE,
  originProcessDied = FALSE,
  twoMinutesElapsed = FALSE,
  originSaeReachable = TRUE,
  laterAttemptReadOrigin = FALSE,
  originDeviceHasKeys = FALSE,
  peerDeviceHasKeys = FALSE,
  terminalReportedSuccess = FALSE;

begin
  ReserveOriginPair:
    originRecord := Synchronization || originReservationExpired := FALSE;
  ReservePeerPair:
    either
      peerRecord := Synchronization || peerReservationExpired := FALSE;
    or
      originProcessDied := TRUE;
      goto ElapseReservationTimeout;
    end either;
  LockOriginFetch:
    either
      originRecord := FetchLocked || originReservationExpired := FALSE;
    or
      originProcessDied := TRUE;
      goto ElapseReservationTimeout;
    end either;
  LockPeerFetch:
    either
      peerRecord := FetchLocked || peerReservationExpired := FALSE;
    or
      originProcessDied := TRUE;
      goto ElapseReservationTimeout;
    end either;
  StorePeerKeyMaterial:
    either
      peerHasKeyMaterial := TRUE;
    or
      originProcessDied := TRUE;
      goto ElapseReservationTimeout;
    end either;
  CommitPeerShare:
    either
      peerRecord := ShareCommitted || peerReservationExpired := FALSE;
    or
      originProcessDied := TRUE;
      goto ElapseReservationTimeout;
    end either;
  CommitOriginShare:
    either
      originRecord := ShareCommitted || originReservationExpired := FALSE || originHasShare := TRUE;
    or
      originProcessDied := TRUE;
      goto ElapseReservationTimeout;
    end either;
  SendToOriginDevice:
    either
      originDeviceHasKeys := TRUE;
    or
      originProcessDied := TRUE;
      goto ElapseReservationTimeout;
    end either;
  MarkOriginProvisioned:
    either
      if originDeviceHasKeys /\ originRecord = ShareCommitted then
        originRecord := OriginProvisioned || originReservationExpired := FALSE;
      end if;
    or
      originProcessDied := TRUE;
      goto ElapseReservationTimeout;
    end either;
  ReportTerminalSuccess:
    either
      if originRecord = OriginProvisioned /\ originDeviceHasKeys
         /\ peerRecord = ShareCommitted /\ originHasShare /\ peerHasKeyMaterial then
        terminalReportedSuccess := TRUE;
      end if;
    or
      \* Process died after the mark returned, before the terminal line.
      skip;
    end either;
  ElapseReservationTimeout:
    either
      twoMinutesElapsed := TRUE
      || originReservationExpired := IF originRecord \in {Synchronization, FetchLocked, ShareCommitted} THEN TRUE ELSE originReservationExpired
      || peerReservationExpired := IF peerRecord \in {Synchronization, FetchLocked, ShareCommitted} THEN TRUE ELSE peerReservationExpired;
    or
      skip;
    end either;
  MaybeLoseOriginLink:
    either
      originSaeReachable := FALSE;
    or
      skip;
    end either;
  LaterAttempt:
    either
      \* Origin retries. Leftover ShareCommitted is a failed origin fill:
      \* delete both rows and reserve again, no operator prompt.
      \* A fresh Synchronization plus leftover peer ShareCommitted → delete
      \* peer, then drop the origin row.
      if originRecord = ShareCommitted then
        originRecord := Synchronization || originReservationExpired := FALSE || originHasShare := FALSE
        || peerRecord := NoRecord || peerReservationExpired := FALSE || peerHasKeyMaterial := FALSE
        || laterAttemptReadOrigin := twoMinutesElapsed \/ laterAttemptReadOrigin;
      elsif originRecord = NoRecord \/ (originRecord \in {Synchronization, FetchLocked} /\ originReservationExpired) then
        if peerRecord = ShareCommitted then
          if originSaeReachable then
            originRecord := NoRecord || originReservationExpired := FALSE || originHasShare := FALSE
            || peerRecord := NoRecord || peerReservationExpired := FALSE || peerHasKeyMaterial := FALSE
            || laterAttemptReadOrigin := twoMinutesElapsed \/ laterAttemptReadOrigin;
          else
            originRecord := NoRecord || originReservationExpired := FALSE || originHasShare := FALSE
            || laterAttemptReadOrigin := twoMinutesElapsed \/ laterAttemptReadOrigin;
          end if;
        else
          originRecord := Synchronization || originReservationExpired := FALSE;
        end if;
      end if;
    or
      \* Second device on the peer: deliver stored material only if origin is
      \* OriginProvisioned. Delete-before-send; the `or skip` is death after delete.
      if peerRecord = ShareCommitted then
        if originSaeReachable = FALSE then
          laterAttemptReadOrigin := twoMinutesElapsed \/ laterAttemptReadOrigin;
        elsif originRecord = OriginProvisioned then
          either
            originRecord := NoRecord || originReservationExpired := FALSE || originHasShare := FALSE
            || peerRecord := NoRecord || peerReservationExpired := FALSE || peerHasKeyMaterial := FALSE
            || peerDeviceHasKeys := TRUE
            || laterAttemptReadOrigin := twoMinutesElapsed \/ laterAttemptReadOrigin;
          or
            originRecord := NoRecord || originReservationExpired := FALSE || originHasShare := FALSE
            || peerRecord := NoRecord || peerReservationExpired := FALSE || peerHasKeyMaterial := FALSE
            || laterAttemptReadOrigin := twoMinutesElapsed \/ laterAttemptReadOrigin;
          end either;
        elsif originRecord \in {ShareCommitted, FetchLocked} then
          if originReservationExpired then
            originRecord := NoRecord || originReservationExpired := FALSE || originHasShare := FALSE
            || peerRecord := NoRecord || peerReservationExpired := FALSE || peerHasKeyMaterial := FALSE
            || laterAttemptReadOrigin := twoMinutesElapsed \/ laterAttemptReadOrigin;
          else
            laterAttemptReadOrigin := twoMinutesElapsed \/ laterAttemptReadOrigin;
          end if;
        elsif originRecord = Synchronization then
          if originReservationExpired then
            originRecord := NoRecord || originReservationExpired := FALSE || originHasShare := FALSE
            || peerRecord := NoRecord || peerReservationExpired := FALSE || peerHasKeyMaterial := FALSE
            || laterAttemptReadOrigin := twoMinutesElapsed \/ laterAttemptReadOrigin;
          else
            peerRecord := NoRecord || peerReservationExpired := FALSE || peerHasKeyMaterial := FALSE
            || laterAttemptReadOrigin := twoMinutesElapsed \/ laterAttemptReadOrigin;
          end if;
        elsif originRecord = NoRecord then
          peerRecord := NoRecord || peerReservationExpired := FALSE || peerHasKeyMaterial := FALSE
          || laterAttemptReadOrigin := twoMinutesElapsed \/ laterAttemptReadOrigin;
        else
          laterAttemptReadOrigin := twoMinutesElapsed \/ laterAttemptReadOrigin;
        end if;
      end if;
    or
      skip;
    end either;
end algorithm; *)

\* BEGIN TRANSLATION
VARIABLES pc, originRecord, originReservationExpired, originHasShare, 
          peerRecord, peerReservationExpired, peerHasKeyMaterial, 
          originProcessDied, twoMinutesElapsed, originSaeReachable, 
          laterAttemptReadOrigin, originDeviceHasKeys, peerDeviceHasKeys, 
          terminalReportedSuccess

vars == << pc, originRecord, originReservationExpired, originHasShare, 
           peerRecord, peerReservationExpired, peerHasKeyMaterial, 
           originProcessDied, twoMinutesElapsed, originSaeReachable, 
           laterAttemptReadOrigin, originDeviceHasKeys, peerDeviceHasKeys, 
           terminalReportedSuccess >>

Init == (* Global variables *)
        /\ originRecord = NoRecord
        /\ originReservationExpired = FALSE
        /\ originHasShare = FALSE
        /\ peerRecord = NoRecord
        /\ peerReservationExpired = FALSE
        /\ peerHasKeyMaterial = FALSE
        /\ originProcessDied = FALSE
        /\ twoMinutesElapsed = FALSE
        /\ originSaeReachable = TRUE
        /\ laterAttemptReadOrigin = FALSE
        /\ originDeviceHasKeys = FALSE
        /\ peerDeviceHasKeys = FALSE
        /\ terminalReportedSuccess = FALSE
        /\ pc = "ReserveOriginPair"

ReserveOriginPair == /\ pc = "ReserveOriginPair"
                     /\ /\ originRecord' = Synchronization
                        /\ originReservationExpired' = FALSE
                     /\ pc' = "ReservePeerPair"
                     /\ UNCHANGED << originHasShare, peerRecord, 
                                     peerReservationExpired, 
                                     peerHasKeyMaterial, originProcessDied, 
                                     twoMinutesElapsed, originSaeReachable, 
                                     laterAttemptReadOrigin, 
                                     originDeviceHasKeys, peerDeviceHasKeys, 
                                     terminalReportedSuccess >>

ReservePeerPair == /\ pc = "ReservePeerPair"
                   /\ \/ /\ /\ peerRecord' = Synchronization
                            /\ peerReservationExpired' = FALSE
                         /\ pc' = "LockOriginFetch"
                         /\ UNCHANGED originProcessDied
                      \/ /\ originProcessDied' = TRUE
                         /\ pc' = "ElapseReservationTimeout"
                         /\ UNCHANGED <<peerRecord, peerReservationExpired>>
                   /\ UNCHANGED << originRecord, originReservationExpired, 
                                   originHasShare, peerHasKeyMaterial, 
                                   twoMinutesElapsed, originSaeReachable, 
                                   laterAttemptReadOrigin, originDeviceHasKeys, 
                                   peerDeviceHasKeys, terminalReportedSuccess >>

LockOriginFetch == /\ pc = "LockOriginFetch"
                   /\ \/ /\ /\ originRecord' = FetchLocked
                            /\ originReservationExpired' = FALSE
                         /\ pc' = "LockPeerFetch"
                         /\ UNCHANGED originProcessDied
                      \/ /\ originProcessDied' = TRUE
                         /\ pc' = "ElapseReservationTimeout"
                         /\ UNCHANGED <<originRecord, originReservationExpired>>
                   /\ UNCHANGED << originHasShare, peerRecord, 
                                   peerReservationExpired, peerHasKeyMaterial, 
                                   twoMinutesElapsed, originSaeReachable, 
                                   laterAttemptReadOrigin, originDeviceHasKeys, 
                                   peerDeviceHasKeys, terminalReportedSuccess >>

LockPeerFetch == /\ pc = "LockPeerFetch"
                 /\ \/ /\ /\ peerRecord' = FetchLocked
                          /\ peerReservationExpired' = FALSE
                       /\ pc' = "StorePeerKeyMaterial"
                       /\ UNCHANGED originProcessDied
                    \/ /\ originProcessDied' = TRUE
                       /\ pc' = "ElapseReservationTimeout"
                       /\ UNCHANGED <<peerRecord, peerReservationExpired>>
                 /\ UNCHANGED << originRecord, originReservationExpired, 
                                 originHasShare, peerHasKeyMaterial, 
                                 twoMinutesElapsed, originSaeReachable, 
                                 laterAttemptReadOrigin, originDeviceHasKeys, 
                                 peerDeviceHasKeys, terminalReportedSuccess >>

StorePeerKeyMaterial == /\ pc = "StorePeerKeyMaterial"
                        /\ \/ /\ peerHasKeyMaterial' = TRUE
                              /\ pc' = "CommitPeerShare"
                              /\ UNCHANGED originProcessDied
                           \/ /\ originProcessDied' = TRUE
                              /\ pc' = "ElapseReservationTimeout"
                              /\ UNCHANGED peerHasKeyMaterial
                        /\ UNCHANGED << originRecord, originReservationExpired, 
                                        originHasShare, peerRecord, 
                                        peerReservationExpired, 
                                        twoMinutesElapsed, originSaeReachable, 
                                        laterAttemptReadOrigin, 
                                        originDeviceHasKeys, peerDeviceHasKeys, 
                                        terminalReportedSuccess >>

CommitPeerShare == /\ pc = "CommitPeerShare"
                   /\ \/ /\ /\ peerRecord' = ShareCommitted
                            /\ peerReservationExpired' = FALSE
                         /\ pc' = "CommitOriginShare"
                         /\ UNCHANGED originProcessDied
                      \/ /\ originProcessDied' = TRUE
                         /\ pc' = "ElapseReservationTimeout"
                         /\ UNCHANGED <<peerRecord, peerReservationExpired>>
                   /\ UNCHANGED << originRecord, originReservationExpired, 
                                   originHasShare, peerHasKeyMaterial, 
                                   twoMinutesElapsed, originSaeReachable, 
                                   laterAttemptReadOrigin, originDeviceHasKeys, 
                                   peerDeviceHasKeys, terminalReportedSuccess >>

CommitOriginShare == /\ pc = "CommitOriginShare"
                     /\ \/ /\ /\ originHasShare' = TRUE
                              /\ originRecord' = ShareCommitted
                              /\ originReservationExpired' = FALSE
                           /\ pc' = "SendToOriginDevice"
                           /\ UNCHANGED originProcessDied
                        \/ /\ originProcessDied' = TRUE
                           /\ pc' = "ElapseReservationTimeout"
                           /\ UNCHANGED <<originRecord, originReservationExpired, originHasShare>>
                     /\ UNCHANGED << peerRecord, peerReservationExpired, 
                                     peerHasKeyMaterial, twoMinutesElapsed, 
                                     originSaeReachable, 
                                     laterAttemptReadOrigin, 
                                     originDeviceHasKeys, peerDeviceHasKeys, 
                                     terminalReportedSuccess >>

SendToOriginDevice == /\ pc = "SendToOriginDevice"
                      /\ \/ /\ originDeviceHasKeys' = TRUE
                            /\ pc' = "MarkOriginProvisioned"
                            /\ UNCHANGED originProcessDied
                         \/ /\ originProcessDied' = TRUE
                            /\ pc' = "ElapseReservationTimeout"
                            /\ UNCHANGED originDeviceHasKeys
                      /\ UNCHANGED << originRecord, originReservationExpired, 
                                      originHasShare, peerRecord, 
                                      peerReservationExpired, 
                                      peerHasKeyMaterial, twoMinutesElapsed, 
                                      originSaeReachable, 
                                      laterAttemptReadOrigin, 
                                      peerDeviceHasKeys, 
                                      terminalReportedSuccess >>

MarkOriginProvisioned == /\ pc = "MarkOriginProvisioned"
                         /\ \/ /\ IF originDeviceHasKeys /\ originRecord = ShareCommitted
                                     THEN /\ /\ originRecord' = OriginProvisioned
                                             /\ originReservationExpired' = FALSE
                                     ELSE /\ TRUE
                                          /\ UNCHANGED << originRecord, 
                                                          originReservationExpired >>
                               /\ pc' = "ReportTerminalSuccess"
                               /\ UNCHANGED originProcessDied
                            \/ /\ originProcessDied' = TRUE
                               /\ pc' = "ElapseReservationTimeout"
                               /\ UNCHANGED <<originRecord, originReservationExpired>>
                         /\ UNCHANGED << originHasShare, peerRecord, 
                                         peerReservationExpired, 
                                         peerHasKeyMaterial, twoMinutesElapsed, 
                                         originSaeReachable, 
                                         laterAttemptReadOrigin, 
                                         originDeviceHasKeys, 
                                         peerDeviceHasKeys, 
                                         terminalReportedSuccess >>

ReportTerminalSuccess == /\ pc = "ReportTerminalSuccess"
                         /\ \/ /\ IF originRecord = OriginProvisioned /\ originDeviceHasKeys
                                     /\ peerRecord = ShareCommitted /\ originHasShare /\ peerHasKeyMaterial
                                     THEN /\ terminalReportedSuccess' = TRUE
                                     ELSE /\ TRUE
                                          /\ UNCHANGED terminalReportedSuccess
                            \/ /\ TRUE
                               /\ UNCHANGED terminalReportedSuccess
                         /\ pc' = "ElapseReservationTimeout"
                         /\ UNCHANGED << originRecord, 
                                         originReservationExpired, 
                                         originHasShare, peerRecord, 
                                         peerReservationExpired, 
                                         peerHasKeyMaterial, originProcessDied, 
                                         twoMinutesElapsed, originSaeReachable, 
                                         laterAttemptReadOrigin, 
                                         originDeviceHasKeys, 
                                         peerDeviceHasKeys >>

ElapseReservationTimeout == /\ pc = "ElapseReservationTimeout"
                            /\ \/ /\ /\ originReservationExpired' = (IF originRecord \in {Synchronization, FetchLocked, ShareCommitted} THEN TRUE ELSE originReservationExpired)
                                     /\ peerReservationExpired' = (IF peerRecord \in {Synchronization, FetchLocked, ShareCommitted} THEN TRUE ELSE peerReservationExpired)
                                     /\ twoMinutesElapsed' = TRUE
                               \/ /\ TRUE
                                  /\ UNCHANGED <<originReservationExpired, peerReservationExpired, twoMinutesElapsed>>
                            /\ pc' = "MaybeLoseOriginLink"
                            /\ UNCHANGED << originRecord, originHasShare, 
                                            peerRecord, peerHasKeyMaterial, 
                                            originProcessDied, 
                                            originSaeReachable, 
                                            laterAttemptReadOrigin, 
                                            originDeviceHasKeys, 
                                            peerDeviceHasKeys, 
                                            terminalReportedSuccess >>

MaybeLoseOriginLink == /\ pc = "MaybeLoseOriginLink"
                       /\ \/ /\ originSaeReachable' = FALSE
                          \/ /\ TRUE
                             /\ UNCHANGED originSaeReachable
                       /\ pc' = "LaterAttempt"
                       /\ UNCHANGED << originRecord, originReservationExpired, 
                                       originHasShare, peerRecord, 
                                       peerReservationExpired, 
                                       peerHasKeyMaterial, originProcessDied, 
                                       twoMinutesElapsed, 
                                       laterAttemptReadOrigin, 
                                       originDeviceHasKeys, peerDeviceHasKeys, 
                                       terminalReportedSuccess >>

LaterAttempt == /\ pc = "LaterAttempt"
                /\ \/ /\ IF originRecord = ShareCommitted
                            THEN /\ /\ laterAttemptReadOrigin' = (twoMinutesElapsed \/ laterAttemptReadOrigin)
                                    /\ originHasShare' = FALSE
                                    /\ originRecord' = Synchronization
                                    /\ originReservationExpired' = FALSE
                                    /\ peerHasKeyMaterial' = FALSE
                                    /\ peerRecord' = NoRecord
                                    /\ peerReservationExpired' = FALSE
                            ELSE /\ IF originRecord = NoRecord \/ (originRecord \in {Synchronization, FetchLocked} /\ originReservationExpired)
                                       THEN /\ IF peerRecord = ShareCommitted
                                                  THEN /\ IF originSaeReachable
                                                             THEN /\ /\ laterAttemptReadOrigin' = (twoMinutesElapsed \/ laterAttemptReadOrigin)
                                                                     /\ originHasShare' = FALSE
                                                                     /\ originRecord' = NoRecord
                                                                     /\ originReservationExpired' = FALSE
                                                                     /\ peerHasKeyMaterial' = FALSE
                                                                     /\ peerRecord' = NoRecord
                                                                     /\ peerReservationExpired' = FALSE
                                                             ELSE /\ /\ laterAttemptReadOrigin' = (twoMinutesElapsed \/ laterAttemptReadOrigin)
                                                                     /\ originHasShare' = FALSE
                                                                     /\ originRecord' = NoRecord
                                                                     /\ originReservationExpired' = FALSE
                                                                  /\ UNCHANGED << peerRecord, 
                                                                                  peerReservationExpired, 
                                                                                  peerHasKeyMaterial >>
                                                  ELSE /\ /\ originRecord' = Synchronization
                                                          /\ originReservationExpired' = FALSE
                                                       /\ UNCHANGED << originHasShare, 
                                                                       peerRecord, 
                                                                       peerReservationExpired, 
                                                                       peerHasKeyMaterial, 
                                                                       laterAttemptReadOrigin >>
                                       ELSE /\ TRUE
                                            /\ UNCHANGED << originRecord, 
                                                            originReservationExpired, 
                                                            originHasShare, 
                                                            peerRecord, 
                                                            peerReservationExpired, 
                                                            peerHasKeyMaterial, 
                                                            laterAttemptReadOrigin >>
                      /\ UNCHANGED peerDeviceHasKeys
                   \/ /\ IF peerRecord = ShareCommitted
                            THEN /\ IF originSaeReachable = FALSE
                                       THEN /\ laterAttemptReadOrigin' = (twoMinutesElapsed \/ laterAttemptReadOrigin)
                                            /\ UNCHANGED << originRecord, 
                                                            originReservationExpired, 
                                                            originHasShare, 
                                                            peerRecord, 
                                                            peerReservationExpired, 
                                                            peerHasKeyMaterial, 
                                                            peerDeviceHasKeys >>
                                       ELSE /\ IF originRecord = OriginProvisioned
                                                  THEN /\ \/ /\ /\ laterAttemptReadOrigin' = (twoMinutesElapsed \/ laterAttemptReadOrigin)
                                                                /\ originHasShare' = FALSE
                                                                /\ originRecord' = NoRecord
                                                                /\ originReservationExpired' = FALSE
                                                                /\ peerDeviceHasKeys' = TRUE
                                                                /\ peerHasKeyMaterial' = FALSE
                                                                /\ peerRecord' = NoRecord
                                                                /\ peerReservationExpired' = FALSE
                                                          \/ /\ /\ laterAttemptReadOrigin' = (twoMinutesElapsed \/ laterAttemptReadOrigin)
                                                                /\ originHasShare' = FALSE
                                                                /\ originRecord' = NoRecord
                                                                /\ originReservationExpired' = FALSE
                                                                /\ peerHasKeyMaterial' = FALSE
                                                                /\ peerRecord' = NoRecord
                                                                /\ peerReservationExpired' = FALSE
                                                             /\ UNCHANGED peerDeviceHasKeys
                                                  ELSE /\ IF originRecord \in {ShareCommitted, FetchLocked}
                                                             THEN /\ IF originReservationExpired
                                                                        THEN /\ /\ laterAttemptReadOrigin' = (twoMinutesElapsed \/ laterAttemptReadOrigin)
                                                                                /\ originHasShare' = FALSE
                                                                                /\ originRecord' = NoRecord
                                                                                /\ originReservationExpired' = FALSE
                                                                                /\ peerHasKeyMaterial' = FALSE
                                                                                /\ peerRecord' = NoRecord
                                                                                /\ peerReservationExpired' = FALSE
                                                                        ELSE /\ laterAttemptReadOrigin' = (twoMinutesElapsed \/ laterAttemptReadOrigin)
                                                                             /\ UNCHANGED << originRecord, 
                                                                                             originReservationExpired, 
                                                                                             originHasShare, 
                                                                                             peerRecord, 
                                                                                             peerReservationExpired, 
                                                                                             peerHasKeyMaterial >>
                                                             ELSE /\ IF originRecord = Synchronization
                                                                        THEN /\ IF originReservationExpired
                                                                                   THEN /\ /\ laterAttemptReadOrigin' = (twoMinutesElapsed \/ laterAttemptReadOrigin)
                                                                                           /\ originHasShare' = FALSE
                                                                                           /\ originRecord' = NoRecord
                                                                                           /\ originReservationExpired' = FALSE
                                                                                           /\ peerHasKeyMaterial' = FALSE
                                                                                           /\ peerRecord' = NoRecord
                                                                                           /\ peerReservationExpired' = FALSE
                                                                                   ELSE /\ /\ laterAttemptReadOrigin' = (twoMinutesElapsed \/ laterAttemptReadOrigin)
                                                                                           /\ peerHasKeyMaterial' = FALSE
                                                                                           /\ peerRecord' = NoRecord
                                                                                           /\ peerReservationExpired' = FALSE
                                                                                        /\ UNCHANGED << originRecord, 
                                                                                                        originReservationExpired, 
                                                                                                        originHasShare >>
                                                                        ELSE /\ IF originRecord = NoRecord
                                                                                   THEN /\ /\ laterAttemptReadOrigin' = (twoMinutesElapsed \/ laterAttemptReadOrigin)
                                                                                           /\ peerHasKeyMaterial' = FALSE
                                                                                           /\ peerRecord' = NoRecord
                                                                                           /\ peerReservationExpired' = FALSE
                                                                                   ELSE /\ laterAttemptReadOrigin' = (twoMinutesElapsed \/ laterAttemptReadOrigin)
                                                                                        /\ UNCHANGED << peerRecord, 
                                                                                                        peerReservationExpired, 
                                                                                                        peerHasKeyMaterial >>
                                                                             /\ UNCHANGED << originRecord, 
                                                                                             originReservationExpired, 
                                                                                             originHasShare >>
                                                       /\ UNCHANGED peerDeviceHasKeys
                            ELSE /\ TRUE
                                 /\ UNCHANGED << originRecord, 
                                                 originReservationExpired, 
                                                 originHasShare, peerRecord, 
                                                 peerReservationExpired, 
                                                 peerHasKeyMaterial, 
                                                 laterAttemptReadOrigin, 
                                                 peerDeviceHasKeys >>
                   \/ /\ TRUE
                      /\ UNCHANGED <<originRecord, originReservationExpired, originHasShare, peerRecord, peerReservationExpired, peerHasKeyMaterial, laterAttemptReadOrigin, peerDeviceHasKeys>>
                /\ pc' = "Done"
                /\ UNCHANGED << originProcessDied, twoMinutesElapsed, 
                                originSaeReachable, originDeviceHasKeys, 
                                terminalReportedSuccess >>

(* Allow infinite stuttering to prevent deadlock on termination. *)
Terminating == pc = "Done" /\ UNCHANGED vars

Next == ReserveOriginPair \/ ReservePeerPair \/ LockOriginFetch
           \/ LockPeerFetch \/ StorePeerKeyMaterial \/ CommitPeerShare
           \/ CommitOriginShare \/ SendToOriginDevice \/ MarkOriginProvisioned
           \/ ReportTerminalSuccess \/ ElapseReservationTimeout
           \/ MaybeLoseOriginLink \/ LaterAttempt
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
  /\ twoMinutesElapsed \in BOOLEAN
  /\ originSaeReachable \in BOOLEAN
  /\ laterAttemptReadOrigin \in BOOLEAN
  /\ originDeviceHasKeys \in BOOLEAN
  /\ peerDeviceHasKeys \in BOOLEAN
  /\ terminalReportedSuccess \in BOOLEAN
  /\ originHasShare \in BOOLEAN
  /\ peerHasKeyMaterial \in BOOLEAN

MatchingSharesWhenCommitted ==
  (originRecord \in {ShareCommitted, OriginProvisioned} /\ peerRecord = ShareCommitted)
    => originHasShare = peerHasKeyMaterial

PeerRowNeverProvisioned == peerRecord # OriginProvisioned

ProvisionedMeansOriginDeviceHasKeys == (originRecord = OriginProvisioned) => originDeviceHasKeys

PeerDeviceImpliesOriginAlreadyFilled == peerDeviceHasKeys => originDeviceHasKeys

PeerDeviceImpliesShareConsumed == peerDeviceHasKeys => peerRecord = NoRecord

\* Printed only after MarkOriginProvisioned returns a consistent share.
\* A later peer delivery may consume both rows; the flag stays set.
TerminalSuccessMeansConsistentShare ==
  terminalReportedSuccess =>
    /\ originDeviceHasKeys
    /\ \/ /\ originRecord = OriginProvisioned
          /\ peerRecord = ShareCommitted
          /\ originHasShare
          /\ peerHasKeyMaterial
       \/ /\ originRecord = NoRecord
          /\ peerRecord = NoRecord
          /\ originHasShare = FALSE
          /\ peerHasKeyMaterial = FALSE

\* After the reservation window may have expired *and* a later attempt actually
\* read the origin (including a failed read). When the origin SAE is reachable,
\* leftover ShareCommitted whose origin is not OriginProvisioned is gone, or
\* the share is whole, or the second device consumed it.
NoAbandonedShareAfterReachableRead ==
  (pc = "Done" /\ laterAttemptReadOrigin /\ originSaeReachable) =>
    \/ (originRecord = NoRecord /\ peerRecord = NoRecord)
    \/ (originRecord = OriginProvisioned /\ peerRecord = ShareCommitted /\ originHasShare = peerHasKeyMaterial)
    \/ (originRecord = OriginProvisioned /\ peerRecord = NoRecord)
    \/ (originRecord \in {Synchronization, FetchLocked, ShareCommitted} /\ ~originReservationExpired)

=============================================================================
