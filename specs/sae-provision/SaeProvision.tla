------------------------------ MODULE SaeProvision ------------------------------
(***************************************************************************
  Key-share provisioning between SAEs with pair locks (leases with fencing
  tokens). Plain TLA+ (no PlusCal translation), so a crash can end another
  process and late RMI messages are first-class. An abstract model of
  ProvisionSession, PairLocks and NodeCommands in modules/sae-node.

  Each element of Edges is one
  provision attempt <<origin, peer, device>>, all for ONE client pair, so
  every SAE has exactly ONE lock entry for that pair (PairKey = sorted pair
  of client hashes, the same on all SAEs).

  Lock entry lk[n] = [iss, tok, st]
    st = "free"     no entry (iss = 0)
         "held"     the holder is alive and renews it every minute
         "lapsing"  the holder stopped renewing (crashed, stalled, aborted,
                    release RMI failed, or the entry was installed by a late
                    acquire nobody owns); Expire(n) may free it at any time.
  Abstract time: a "held" lease never expires; a "lapsing" one may.

  Rows rec[<<n, device at n>>] = [st ("none" | "ka" = KEYS_AVAILABLE),
    iss, sae (counterpart SAE), tok (token of the writing operation),
    kid (key material: the token of the KME fetch that produced it)].

  Token = <<edge, k>>, fresh for every operation (UUID in Java).

  Operation flow for edge e (O = origin, P = peer), each step atomic:
    lock1   tryAcquire on First (lower id; LockOrder="local": own SAE)
    lock2   tryAcquire on Second; refused -> release first, fail "retry"
    check   read both rows under both locks; existing share -> operator
    kme     KME keys                (KME failure = AbortOp fault)
    xfer    pads to the origin device
    pwrite  RMI: peer writes KEYS_AVAILABLE(tok), fenced by lk[P].tok
    owrite  origin writes KEYS_AVAILABLE(tok), fenced by lk[O].tok
    complete  device gets "share complete"
    relR, relL  release remote first, then local (by token)
  Operator delete of a share between SAEs a and b (a = where the operator
  saw it, b = its counterpart): release the session locks, lock min(a,b)
  then max(a,b) (new token), delete b's row (RMI, fenced), then a's row
  only if b's delete succeeded, release, then re-provision once.
  With DeleteChecksSeen each delete also requires the row's token to be the
  token the operator confirmed (compare-and-delete).
 ***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS Nodes, Edges,
          MaxSessions,      \* sessions (device plug-ins / replugs) per edge
          MaxCrashes, MaxStalls, MaxAborts, MaxLost,
          OperatorDeletes,
          RetryOnRefusal,   \* refusal: retry in the same session (TRUE) or end it
          LockOrder,        \* "lower" (design) | "local" (mutations/mut_a)
          FencePeerWrite,   \* TRUE (design) | FALSE (mutations/mut_b)
          DeleteTakesLocks, \* TRUE (design) | FALSE: the operator delete takes no locks
          DeleteChecksSeen, \* compare-and-delete on the confirmed token (FALSE: mutations/mut_d)
          LeaseGuard        \* after a renewal gap, renew both before the next step (FALSE: mutations/mut_e)

Devices == {"X", "Y"}
Other(d) == IF d = "X" THEN "Y" ELSE "X"
O(e) == e[1]
P(e) == e[2]
OD(e) == e[3]
ORow(e) == <<O(e), OD(e)>>
PRow(e) == <<P(e), Other(OD(e))>>
Rows == Nodes \X Devices
Min(a, b) == IF a < b THEN a ELSE b
Max(a, b) == IF a < b THEN b ELSE a

SingleEdges == {<<1, 2, "X">>}
FanEdges    == {<<1, 2, "X">>, <<3, 1, "Y">>, <<3, 2, "X">>}
ChainEdges  == FanEdges \cup {<<4, 2, "X">>, <<3, 4, "Y">>}
RingEdges   == {<<1, 2, "X">>, <<2, 3, "Y">>, <<3, 4, "X">>, <<4, 1, "Y">>}

ASSUME /\ Nodes \subseteq Nat \ {0}
       /\ Edges \subseteq Nodes \X Nodes \X Devices
       /\ \A e \in Edges : O(e) # P(e)
       /\ LockOrder \in {"lower", "local"}
       /\ RetryOnRefusal => MaxLost = 0   \* the retry reuses the token

\* An operator delete happens at most once per edge (del op + re-provision).
MaxTok == MaxSessions + 2
NoEdge == <<0, 0, "-">>
NoTok == <<NoEdge, 0>>
Toks == Edges \X (1..MaxTok)
FreeEntry == [iss |-> 0, tok |-> NoTok, st |-> "free"]
NoRow == [st |-> "none", iss |-> 0, sae |-> 0, tok |-> NoTok, kid |-> NoTok]
KA(i, s, t) == [st |-> "ka", iss |-> i, sae |-> s, tok |-> t, kid |-> t]

Pcs == {"idle", "lock1", "lock2", "check", "kme", "xfer", "pwrite", "owrite",
        "complete", "delR", "delL", "relR", "relL", "end", "done"}
\* Both locks are (believed) held.
LockedPcs == {"check", "kme", "xfer", "pwrite", "owrite", "complete", "delR", "delL"}

VARIABLES
  lk,    \* lock entry per SAE (one client pair)
  rec,   \* DB rows
  usb,   \* Node.usbLoop: the session running on each SAE
  msgs,  \* late RMI handler executions (reply lost, handler still runs)
  sv,    \* per-edge saga state
  f,     \* fault counters
  g      \* ghost state for the properties

vars == <<lk, rec, usb, msgs, sv, f, g>>

Tok(e) == <<e, sv[e].k>>
OpA(e) == IF sv[e].op = "prov" THEN O(e) ELSE sv[e].dA   \* "local" side
OpB(e) == IF sv[e].op = "prov" THEN P(e) ELSE sv[e].dB   \* "remote" side
First(e)  == IF LockOrder = "lower" THEN Min(OpA(e), OpB(e)) ELSE OpA(e)
Second(e) == IF First(e) = OpA(e) THEN OpB(e) ELSE OpA(e)
Remote(e, n) == n # O(e)

CanAcquire(n, i) == lk[n].iss = 0 \/ lk[n].iss = i
Holds(n, t) == lk[n].iss # 0 /\ lk[n].tok = t
HoldsBoth(e) == Holds(OpA(e), Tok(e)) /\ Holds(OpB(e), Tok(e))
Lapse(l, t) == [n \in Nodes |-> IF l[n].tok = t /\ l[n].st = "held"
                                THEN [l[n] EXCEPT !.st = "lapsing"] ELSE l[n]]

Msg(kind, n, t, i, row, cp, seen, snap) ==
  [kind |-> kind, node |-> n, tok |-> t, iss |-> i, row |-> row, cp |-> cp,
   seen |-> seen, snap |-> snap]

\* The rows of share t are both KEYS_AVAILABLE(t) with t's key material.
ShareIntact(t) ==
  LET e == t[1] IN
  /\ rec[ORow(e)] = KA(O(e), P(e), t)
  /\ rec[PRow(e)] = KA(O(e), O(e), t)

InitSv == [pc |-> "idle", k |-> 0, op |-> "prov", after |-> "end",
           dA |-> 0, dB |-> 0, rA |-> <<0, "X">>, rB |-> <<0, "X">>,
           seen |-> NoTok, snap |-> {}, opDel |-> FALSE, sess |-> 0,
           rdOk |-> FALSE, out |-> "none", gap |-> FALSE]

Init ==
  /\ lk = [n \in Nodes |-> FreeEntry]
  /\ rec = [r \in Rows |-> NoRow]
  /\ usb = [n \in Nodes |-> NoEdge]
  /\ msgs = {}
  /\ sv = [e \in Edges |-> InitSv]
  /\ f = [crashes |-> 0, stalls |-> 0, aborts |-> 0, lost |-> 0]
  /\ g = [devHas |-> {}, completed |-> {}, opDeleted |-> {},
          termBad |-> FALSE, originBeforePeer |-> FALSE,
          delUnconfirmed |-> FALSE, delNotAtLock |-> FALSE,
          localNoRemote |-> FALSE]

SetSv(e, s) == sv' = [sv EXCEPT ![e] = s]
\* Forget the fields of a finished delete (keeps the state space small).
Clean(s) == [s EXCEPT !.dA = 0, !.dB = 0, !.rA = <<0, "X">>, !.rB = <<0, "X">>,
                      !.seen = NoTok, !.snap = {}, !.rdOk = FALSE]
Fail(s) == [s EXCEPT !.out = "fail", !.after = "end", !.pc = "relR", !.gap = FALSE]

-----------------------------------------------------------------------------
\* Saga steps (normal outcomes; these get weak fairness).

Start(e) ==
  /\ sv[e].pc = "idle"
  /\ usb[O(e)] = NoEdge
  /\ usb' = [usb EXCEPT ![O(e)] = e]
  /\ SetSv(e, [sv[e] EXCEPT !.pc = "lock1", !.k = @ + 1, !.sess = @ + 1,
                            !.op = "prov", !.out = "none", !.rdOk = FALSE, !.gap = FALSE])
  /\ UNCHANGED <<lk, rec, msgs, f, g>>

\* Snapshot of the rows a delete may touch, at the moment it holds both locks.
Snap(e) == {rec[sv[e].rA].tok, rec[sv[e].rB].tok}

Lock1(e) ==
  /\ sv[e].pc = "lock1"
  /\ IF sv[e].op = "del" /\ ~DeleteTakesLocks
     THEN \* DeleteTakesLocks = FALSE: the delete skips both locks (and their fencing)
          /\ SetSv(e, [sv[e] EXCEPT !.pc = "delR", !.snap = Snap(e)])
          /\ UNCHANGED lk
     ELSE LET n == First(e) IN
          IF CanAcquire(n, O(e))
          THEN /\ lk' = [lk EXCEPT ![n] = [iss |-> O(e), tok |-> Tok(e), st |-> "held"]]
               /\ SetSv(e, [sv[e] EXCEPT !.pc = "lock2"])
          ELSE /\ ~RetryOnRefusal   \* with retry: the step waits (no state change)
               /\ SetSv(e, [sv[e] EXCEPT !.pc = "end", !.out = "refused"])
               /\ UNCHANGED lk
  /\ UNCHANGED <<rec, usb, msgs, f, g>>

Lock2(e) ==
  /\ sv[e].pc = "lock2"
  /\ LET n == Second(e) IN
     IF CanAcquire(n, O(e))
     THEN /\ lk' = [lk EXCEPT ![n] = [iss |-> O(e), tok |-> Tok(e), st |-> "held"]]
          /\ IF sv[e].op = "prov"
             THEN SetSv(e, [sv[e] EXCEPT !.pc = "check"])
             ELSE SetSv(e, [sv[e] EXCEPT !.pc = "delR",
                       !.snap = {rec[sv[e].rA].tok, rec[sv[e].rB].tok}])
     ELSE /\ SetSv(e, [sv[e] EXCEPT !.pc = "relR", !.out = "refused",
                       !.after = IF RetryOnRefusal THEN "retry" ELSE "end"])
          /\ UNCHANGED lk
  /\ UNCHANGED <<rec, usb, msgs, f, g>>

Keep(e) == SetSv(e, [sv[e] EXCEPT !.pc = "relR", !.out = "kept", !.after = "end"])

\* Operator chose "delete existing share" for a share between a and b seen
\* in rows ra (on a) and rb (on b) with token st.
StartDelete(e, a, b, ra, rb, st) ==
  /\ OperatorDeletes /\ ~sv[e].opDel
  /\ SetSv(e, [sv[e] EXCEPT !.opDel = TRUE, !.seen = st, !.dA = a, !.dB = b,
                            !.rA = ra, !.rB = rb, !.after = "del", !.pc = "relR"])

Check(e) ==
  /\ sv[e].pc = "check"
  /\ LET lr == rec[ORow(e)]
         pr == rec[PRow(e)]
     IN IF lr.st = "ka" /\ lr.sae # P(e) THEN
          \* local share with another SAE q
          \/ Keep(e)
          \/ StartDelete(e, O(e), lr.sae, ORow(e), <<lr.sae, Other(OD(e))>>, lr.tok)
        ELSE IF pr.st = "ka" /\ pr.sae # O(e) THEN
          \* the peer has a share with another SAE r (handover delete)
          \/ Keep(e)
          \/ StartDelete(e, P(e), pr.sae, PRow(e), <<pr.sae, OD(e)>>, pr.tok)
        ELSE IF lr.st = "ka" /\ pr.st = "ka" /\ lr.tok = pr.tok THEN
          \* existing O<->P share: keep, or delete it under the held locks
          \/ Keep(e)
          \/ /\ OperatorDeletes /\ ~sv[e].opDel
             /\ SetSv(e, [sv[e] EXCEPT !.opDel = TRUE, !.seen = lr.tok,
                          !.dA = O(e), !.dB = P(e), !.rA = ORow(e), !.rB = PRow(e),
                          !.snap = {lr.tok, pr.tok}, !.pc = "delR"])
        ELSE
          \* nothing, or non-matching rows: overwritten under both locks
          SetSv(e, [sv[e] EXCEPT !.pc = "kme"])
  /\ UNCHANGED <<lk, rec, usb, msgs, f, g>>

Kme(e) ==
  /\ sv[e].pc = "kme"
  /\ SetSv(e, [sv[e] EXCEPT !.pc = "xfer"])
  /\ UNCHANGED <<lk, rec, usb, msgs, f, g>>

Xfer(e) ==
  /\ sv[e].pc = "xfer"
  /\ SetSv(e, [sv[e] EXCEPT !.pc = "pwrite"])
  /\ g' = [g EXCEPT !.devHas = @ \cup {Tok(e)}]
  /\ UNCHANGED <<lk, rec, usb, msgs, f>>

PeerWriteOk(n, t) == ~FencePeerWrite \/ Holds(n, t)

PWrite(e) ==
  /\ sv[e].pc = "pwrite"
  /\ IF PeerWriteOk(P(e), Tok(e))
     THEN /\ rec' = [rec EXCEPT ![PRow(e)] = KA(O(e), O(e), Tok(e))]
          /\ SetSv(e, [sv[e] EXCEPT !.pc = "owrite"])
     ELSE /\ SetSv(e, Fail(sv[e]))
          /\ UNCHANGED rec
  /\ UNCHANGED <<lk, usb, msgs, f, g>>

OWrite(e) ==
  /\ sv[e].pc = "owrite"
  /\ IF Holds(O(e), Tok(e))
     THEN /\ rec' = [rec EXCEPT ![ORow(e)] = KA(O(e), P(e), Tok(e))]
          /\ SetSv(e, [sv[e] EXCEPT !.pc = "complete"])
          /\ g' = [g EXCEPT !.originBeforePeer = @ \/
                              rec[PRow(e)] # KA(O(e), O(e), Tok(e))]
     ELSE /\ SetSv(e, Fail(sv[e]))
          /\ UNCHANGED <<rec, g>>
  /\ UNCHANGED <<lk, usb, msgs, f>>

Complete(e) ==
  /\ sv[e].pc = "complete"
  /\ g' = [g EXCEPT !.completed = @ \cup {Tok(e)},
                    !.termBad = @ \/ ~(ShareIntact(Tok(e)) /\ Tok(e) \in g.devHas)]
  /\ SetSv(e, [sv[e] EXCEPT !.pc = "relR", !.out = "success", !.after = "end"])
  /\ UNCHANGED <<lk, rec, usb, msgs, f>>

\* Effect of a delete handler on row r of SAE n (counterpart cp) for token t.
\* Returns <<ok, newRec, newG>>; ok = FALSE means refused.
DelEffect(n, r, cp, t, seen, snap, fenced) ==
  LET row == rec[r]
      match == row.st = "ka" /\ row.sae = cp
      lockOk == ~fenced \/ Holds(n, t)
      seenOk == ~DeleteChecksSeen \/ row.tok = seen
  IN IF ~lockOk \/ (match /\ ~seenOk) THEN <<FALSE, rec, g>>
     ELSE IF ~match THEN <<TRUE, rec, g>>
     ELSE <<TRUE, [rec EXCEPT ![r] = NoRow],
            [g EXCEPT !.opDeleted = @ \cup {row.tok},
                      !.delUnconfirmed = @ \/ row.tok # seen,
                      !.delNotAtLock = @ \/ row.tok \notin snap]>>

DelR(e) ==
  /\ sv[e].pc = "delR"
  /\ LET s == sv[e]
         res == DelEffect(s.dB, s.rB, s.dA, Tok(e), s.seen, s.snap, DeleteTakesLocks)
     IN IF res[1]
        THEN /\ rec' = res[2] /\ g' = res[3]
             /\ SetSv(e, [s EXCEPT !.rdOk = TRUE, !.pc = "delL"])
        ELSE /\ SetSv(e, Fail(s))
             /\ UNCHANGED <<rec, g>>
  /\ UNCHANGED <<lk, usb, msgs, f>>

DelL(e) ==
  /\ sv[e].pc = "delL"
  /\ LET s == sv[e]
         res == DelEffect(s.dA, s.rA, s.dB, Tok(e), s.seen, s.snap, DeleteTakesLocks)
     IN IF res[1]
        THEN /\ rec' = res[2]
             /\ g' = [res[3] EXCEPT !.localNoRemote = @ \/ ~s.rdOk]
             /\ IF s.op = "del"
                THEN SetSv(e, [s EXCEPT !.after = "reprov", !.pc = "relR"])
                ELSE SetSv(e, [Clean(s) EXCEPT !.pc = "kme"])
        ELSE /\ SetSv(e, Fail(s))
             /\ UNCHANGED <<rec, g>>
  /\ UNCHANGED <<lk, usb, msgs, f>>

Release(n, t) == IF Holds(n, t) THEN [lk EXCEPT ![n] = FreeEntry] ELSE lk

RelR(e) ==
  /\ sv[e].pc = "relR"
  /\ lk' = Release(OpB(e), Tok(e))
  /\ SetSv(e, [sv[e] EXCEPT !.pc = "relL"])
  /\ UNCHANGED <<rec, usb, msgs, f, g>>

RelL(e) ==
  /\ sv[e].pc = "relL"
  /\ lk' = Release(OpA(e), Tok(e))
  /\ LET s == sv[e] IN
     CASE s.after = "end"    -> SetSv(e, [s EXCEPT !.pc = "end"])
       [] s.after = "retry"  -> SetSv(e, [s EXCEPT !.pc = "lock1", !.out = "none"])
       [] s.after = "del"    -> SetSv(e, [s EXCEPT !.pc = "lock1", !.op = "del",
                                          !.k = @ + 1, !.rdOk = FALSE])
       [] s.after = "reprov" -> SetSv(e, [Clean(s) EXCEPT !.pc = "lock1", !.op = "prov",
                                          !.k = @ + 1])
  /\ UNCHANGED <<rec, usb, msgs, f, g>>

\* Session ends; entries still carrying this token stop being renewed.
\* After a failure the user may replug (new session, new token).
End(e) ==
  /\ sv[e].pc = "end"
  /\ usb' = [usb EXCEPT ![O(e)] = NoEdge]
  /\ lk' = Lapse(lk, Tok(e))
  /\ \/ /\ sv[e].out \in {"refused", "fail", "crashed"}
        /\ sv[e].sess < MaxSessions
        /\ SetSv(e, [Clean(sv[e]) EXCEPT !.pc = "idle", !.op = "prov",
                                          !.after = "end", !.out = "none"])
     \/ SetSv(e, [Clean(sv[e]) EXCEPT !.pc = "done", !.op = "prov",
                                       !.after = "end", !.out = "none"])
  /\ UNCHANGED <<rec, msgs, f, g>>

\* LeaseGuard: after a renewal gap (Stall) the holder renews its entries
\* (remote via RMI) before any further step; if one does not carry its
\* token (expired and freed or taken, or lost in a crash) it aborts.
Resume(e) ==
  /\ sv[e].gap
  /\ LET held == IF sv[e].pc = "lock2" THEN {First(e)} ELSE {OpA(e), OpB(e)} IN
     IF \A n \in held : Holds(n, Tok(e))
     THEN /\ lk' = [n \in Nodes |-> IF n \in held THEN [lk[n] EXCEPT !.st = "held"] ELSE lk[n]]
          /\ SetSv(e, [sv[e] EXCEPT !.gap = FALSE])
     ELSE /\ SetSv(e, Fail(sv[e]))
          /\ UNCHANGED lk
  /\ UNCHANGED <<rec, usb, msgs, f, g>>

SagaStep0(e) ==
  \/ Start(e) \/ Lock1(e) \/ Lock2(e) \/ Check(e) \/ Kme(e) \/ Xfer(e)
  \/ PWrite(e) \/ OWrite(e) \/ Complete(e) \/ DelR(e) \/ DelL(e)
  \/ RelR(e) \/ RelL(e) \/ End(e)

SagaStep(e) ==
  IF sv[e].gap THEN Resume(e) ELSE SagaStep0(e)

-----------------------------------------------------------------------------
\* Faults (no fairness).

\* An RMI reply is lost: the caller fails, the handler runs later (or never,
\* if it is refused by its token). Remote acquire, peer insert, remote delete.
LostReply(e) ==
  /\ ~sv[e].gap
  /\ f.lost < MaxLost
  /\ f' = [f EXCEPT !.lost = @ + 1]
  /\ LET s == sv[e] t == Tok(e) IN
     \/ /\ s.pc = "lock1" /\ Remote(e, First(e))
        /\ ~(s.op = "del" /\ ~DeleteTakesLocks)
        /\ msgs' = msgs \cup {Msg("acquire", First(e), t, O(e), <<0, "X">>, 0, NoTok, {})}
        /\ SetSv(e, [s EXCEPT !.pc = "end", !.out = "fail"])
     \/ /\ s.pc = "lock2" /\ Remote(e, Second(e))
        /\ msgs' = msgs \cup {Msg("acquire", Second(e), t, O(e), <<0, "X">>, 0, NoTok, {})}
        /\ SetSv(e, Fail(s))
     \/ /\ s.pc = "pwrite"
        /\ msgs' = msgs \cup {Msg("insert", P(e), t, O(e), PRow(e), O(e), NoTok, {})}
        /\ SetSv(e, Fail(s))
     \/ /\ s.pc = "delR"
        /\ msgs' = msgs \cup {Msg("delete", s.dB, t, O(e), s.rB, s.dA, s.seen, s.snap)}
        /\ SetSv(e, Fail(s))
     \/ /\ s.pc = "relR"
        \* release RMI fails: the entry stops being renewed and lapses; the
        \* release handler may still run later
        /\ msgs' = msgs \cup {Msg("release", OpB(e), t, O(e), <<0, "X">>, 0, NoTok, {})}
        /\ SetSv(e, [s EXCEPT !.pc = "relL"])
  /\ lk' = IF sv[e].pc = "relR" THEN Lapse(lk, Tok(e)) ELSE lk
  /\ UNCHANGED <<rec, usb, g>>

\* The holder stalls (GC pause, stuck KME or RMI call) past renewals: its
\* entries lapse and may expire; the saga continues later, fenced by tokens.
Stall(e) ==
  /\ sv[e].pc \in LockedPcs \cup {"lock2"}
  /\ ~sv[e].gap
  /\ f.stalls < MaxStalls
  /\ f' = [f EXCEPT !.stalls = @ + 1]
  /\ lk' = Lapse(lk, Tok(e))
  /\ IF LeaseGuard THEN SetSv(e, [sv[e] EXCEPT !.gap = TRUE]) ELSE UNCHANGED sv
  /\ UNCHANGED <<rec, usb, msgs, g>>

\* KME failure or a failed renewal RMI: the operation aborts itself.
AbortOp(e) ==
  /\ ~sv[e].gap
  /\ sv[e].pc \in LockedPcs
  /\ f.aborts < MaxAborts
  /\ f' = [f EXCEPT !.aborts = @ + 1]
  /\ SetSv(e, Fail(sv[e]))
  /\ UNCHANGED <<lk, rec, usb, msgs, g>>

\* The next renewal finds an entry that does not carry the token (peer
\* crashed, or the lease expired and was taken): the operation aborts.
RenewFails(e) ==
  /\ ~sv[e].gap
  /\ sv[e].pc \in LockedPcs
  /\ DeleteTakesLocks \/ sv[e].op = "prov"
  /\ ~HoldsBoth(e)
  /\ SetSv(e, Fail(sv[e]))
  /\ UNCHANGED <<lk, rec, usb, msgs, f, g>>

\* JVM crash of SAE n: all its lock entries are lost, rows survive, its own
\* session dies (the device never saw "share complete"), its pending
\* handlers die; entries its session held elsewhere lapse.
Crash(n) ==
  /\ f.crashes < MaxCrashes
  /\ f' = [f EXCEPT !.crashes = @ + 1]
  /\ LET e == usb[n]
         l1 == IF e # NoEdge THEN Lapse(lk, Tok(e)) ELSE lk
     IN /\ lk' = [l1 EXCEPT ![n] = FreeEntry]
        /\ sv' = IF e # NoEdge
                 THEN [sv EXCEPT ![e] = [@ EXCEPT !.pc = "end", !.out = "crashed"]]
                 ELSE sv
  /\ msgs' = {m \in msgs : m.node # n}
  /\ UNCHANGED <<rec, usb, g>>

Expire(n) ==
  /\ lk[n].st = "lapsing"
  /\ lk' = [lk EXCEPT ![n] = FreeEntry]
  /\ UNCHANGED <<rec, usb, msgs, sv, f, g>>

\* A late handler runs on m.node, fenced by its token.
Deliver(m) ==
  /\ m \in msgs
  /\ msgs' = msgs \ {m}
  /\ CASE m.kind = "acquire" ->
            /\ lk' = IF CanAcquire(m.node, m.iss)
                     THEN [lk EXCEPT ![m.node] = [iss |-> m.iss, tok |-> m.tok, st |-> "lapsing"]]
                     ELSE lk
            /\ UNCHANGED <<rec, g>>
       [] m.kind = "release" ->
            /\ lk' = Release(m.node, m.tok)
            /\ UNCHANGED <<rec, g>>
       [] m.kind = "insert" ->
            /\ rec' = IF PeerWriteOk(m.node, m.tok)
                      THEN [rec EXCEPT ![m.row] = KA(m.iss, m.cp, m.tok)] ELSE rec
            /\ UNCHANGED <<lk, g>>
       [] m.kind = "delete" ->
            LET res == DelEffect(m.node, m.row, m.cp, m.tok, m.seen, m.snap, DeleteTakesLocks)
            IN /\ rec' = res[2] /\ g' = res[3]
               /\ UNCHANGED lk
  /\ UNCHANGED <<usb, sv, f>>

Terminating == /\ \A e \in Edges : sv[e].pc = "done"
               /\ UNCHANGED vars

Next ==
  \/ \E e \in Edges : SagaStep(e) \/ LostReply(e) \/ Stall(e) \/ AbortOp(e) \/ RenewFails(e)
  \/ \E n \in Nodes : Crash(n) \/ Expire(n)
  \/ \E m \in msgs : Deliver(m)
  \/ Terminating

Spec == /\ Init /\ [][Next]_vars
        /\ \A e \in Edges : WF_vars(SagaStep(e))
        /\ \A n \in Nodes : WF_vars(Expire(n))
        /\ WF_vars(\E m \in msgs : Deliver(m))

-----------------------------------------------------------------------------
\* Properties

TypeOK ==
  /\ lk \in [Nodes -> [iss : Nodes \cup {0}, tok : Toks \cup {NoTok},
                       st : {"free", "held", "lapsing"}]]
  /\ rec \in [Rows -> [st : {"none", "ka"}, iss : Nodes \cup {0}, sae : Nodes \cup {0},
                       tok : Toks \cup {NoTok}, kid : Toks \cup {NoTok}]]
  /\ usb \in [Nodes -> Edges \cup {NoEdge}]
  /\ \A e \in Edges : sv[e].pc \in Pcs /\ sv[e].k \in 0..MaxTok

\* Two different operations that both still hold both of their entries and
\* are inside the locked region never share an SAE. (Structural: one entry
\* per SAE per pair; stated for completeness.)
MutualExclusion ==
  \A e1, e2 \in Edges :
    (/\ e1 # e2 /\ sv[e1].pc \in LockedPcs /\ sv[e2].pc \in LockedPcs
     /\ HoldsBoth(e1) /\ HoldsBoth(e2))
      => {OpA(e1), OpB(e1)} \cap {OpA(e2), OpB(e2)} = {}

\* At "share complete" both rows are KEYS_AVAILABLE with this attempt's
\* token and key material, and the origin device holds those pads.
TerminalSuccessMeansConsistentShare == ~g.termBad

\* The origin writes KEYS_AVAILABLE(tok) only when the peer row already is.
OriginMarkedAfterPeer == ~g.originBeforePeer

\* Two counterpart rows (a's row naming b, b's row naming a) are
\* "available" iff both KEYS_AVAILABLE with the same token.
Available(ra, rb) ==
  /\ ra[2] = Other(rb[2])
  /\ rec[ra].st = "ka" /\ rec[rb].st = "ka"
  /\ rec[ra].sae = rb[1] /\ rec[rb].sae = ra[1]
  /\ rec[ra].tok = rec[rb].tok

\* Same token on both sides => same key material.
MatchingSharesWhenCommitted ==
  \A ra, rb \in Rows : Available(ra, rb) => rec[ra].kid = rec[rb].kid

\* What a use-time check (both sides, same token) would deliver is the
\* attempt's own pads, held by its origin device, at that attempt's rows.
NoMismatchedDelivery ==
  \A ra, rb \in Rows : Available(ra, rb) =>
    LET t == rec[ra].tok IN
    /\ t \in g.devHas
    /\ rec[ra].kid = t
    /\ {ra, rb} = {ORow(t[1]), PRow(t[1])}

\* A share the device was told is complete stays intact until an operator
\* delete removes it.
CompletedShareNotSilentlyLost ==
  \A t \in g.completed : t \in g.opDeleted \/ ShareIntact(t)

\* An operator delete removes only the share the operator confirmed, never
\* a share written by a later operation on the same pair.
OperatorDeleteOnlyConfirmedShare == ~g.delUnconfirmed

\* ... and only rows that were there when it held both locks.
OperatorDeleteOnlyRowsPresentAtLock == ~g.delNotAtLock

\* Remote first: a local delete only after the remote delete succeeded.
RemoteFirstDelete == ~g.localNoRemote

AllSagasFinish == <>(\A e \in Edges : sv[e].pc = "done")
=============================================================================
