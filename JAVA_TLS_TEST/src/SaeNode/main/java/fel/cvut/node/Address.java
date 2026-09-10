package fel.cvut.node;

import java.io.Serializable;

public class Address implements Comparable<Address>, Serializable {
    private static final long serialVersionUID = 1L;
    
    public String hostname;
    public Integer port;


    public Address () {
        this("127.0.0.1", 2010);
    }


    public Address (String hostname, int port) {
        this.hostname = hostname;
        this.port = port;
    }


    public Address (Address addr) {
        this(addr.hostname, addr.port);
    }


    @Override
    public String toString() {
        return("Addr[host:'"+hostname+"', port:'"+port+"']");
    }


    @Override
    public int compareTo(Address address) {
        int retval = 0;
        if ((retval = hostname.compareTo(address.hostname)) == 0 ) {
            retval = port.compareTo(address.port);
        }
        return retval;
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        Address address = (Address) obj;
        return compareTo(address) == 0;
    }
    
    @Override
    public int hashCode() {
        return hostname.hashCode() * 31 + port.hashCode();
    }
}