import io.pkts.Pcap;
import io.pkts.packet.Packet;
import io.pkts.packet.TCPPacket;
import io.pkts.protocol.Protocol;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;




public interface mapperPortList {

    static void TCP(ArrayList<Packet> listTCP){
        try {
            Pcap pcap = Pcap.openStream("C:\\Users\\Zzzoozlezzz\\IdeaProjects\\Packet_Analysis\\src\\main\\resources\\dumb.pcap");
            pcap.loop((final Packet packet) -> {
                if(packet.hasProtocol(Protocol.TCP)) {
                    listTCP.add(packet);
                }
                return true;
            });
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        }
    }

    static void IP(ArrayList<Packet> listIP){
        try {
            Pcap pcap = Pcap.openStream("C:\\Users\\Zzzoozlezzz\\IdeaProjects\\Packet_Analysis\\src\\main\\resources\\dumb.pcap");
            pcap.loop((final Packet packet) -> {
                if(packet.hasProtocol(Protocol.IPv4)) {
                    listIP.add(packet);
                }
                return true;
            });
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        }
    }

    static Set<Integer> Port(ArrayList<Packet> listTCP,ArrayList<Packet> listSYNandACK,ArrayList<Packet> listACK, ArrayList<Packet> listSYN){
        ArrayList<Integer> portList = new ArrayList<>();

        try {
            for (Packet packet : listTCP) {
                TCPPacket temp = (TCPPacket) packet.getPacket(Protocol.TCP);
                portList.add(temp.getDestinationPort());
                if(temp.isSYN() && temp.isACK()){
                    listSYNandACK.add(temp);
                }
                if(temp.isACK()){
                    listACK.add(temp);
                }
                if(temp.isSYN()){
                    listSYN.add(temp);
                }
            }
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        }
        Set<Integer> uniquePorts = new HashSet<>(portList);
        return  uniquePorts;
    }
}
