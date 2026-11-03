package fel.cvut.node.pairlock;

import java.rmi.NotBoundException;
import java.rmi.RemoteException;

/** The pair-lock registry of one SAE, local or reached over RMI. */
public interface PairLockEndpoint {

    String saeId();

    boolean lock(String clientHash1, String clientHash2, String token)
            throws RemoteException, NotBoundException;

    boolean renew(String clientHash1, String clientHash2, String token)
            throws RemoteException, NotBoundException;

    boolean release(String clientHash1, String clientHash2, String token)
            throws RemoteException, NotBoundException;

    /** {@code true} for the registry of this SAE. */
    boolean local();
}
