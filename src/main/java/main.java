import io.pkts.Pcap;
import io.pkts.packet.IPPacket;
import io.pkts.packet.Packet;
import io.pkts.packet.TCPPacket;
import io.pkts.protocol.Protocol;

import java.io.IOException;
import java.util.*;


public class main implements mapperPortList {

    public static void main(String[] args) {
        ArrayList<Packet> listTCP = new ArrayList<>();
        ArrayList<Packet> listIP = new ArrayList<>();
        ArrayList<Packet> listSYNandACK = new ArrayList<>();
        ArrayList<Packet> listSYN = new ArrayList<>();
        ArrayList<Packet> listACK = new ArrayList<>();
        IPPacket packetExample;
        IPPacket packetSYNExample;


        mapperPortList.TCP(listTCP);
        mapperPortList.IP(listIP);

        Set<Integer> uniqueport = mapperPortList.Port(listTCP, listSYNandACK, listACK, listSYN);

        try {
            packetExample = (IPPacket) listIP.get(10).getPacket(Protocol.IPv4);
            packetSYNExample = (IPPacket) listSYN.get(1).getPacket(Protocol.IPv4);
            Boolean checkSYNflood = listSYNandACK.size() > listACK.size();
            System.out.println("1. Сканування порта відбувається з адреси: " + packetExample.getSourceIP());
            System.out.println("2. Хост, що був просканований має адресу: " + packetExample.getDestinationIP());
            System.out.println("3. Кількість просканованих портів: " + uniqueport.size());
            System.out.println("4. SYN-flood: " + checkSYNflood.toString());
            System.out.println("5. Відправник SYN пакетів: " + packetSYNExample.getSourceIP());
            System.out.println("6. Отримувач SYN пакетів: " + packetSYNExample.getDestinationIP());
            System.out.println("7. Кількість SYN пакетів: " + listSYN.size());
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        }
    }
}
