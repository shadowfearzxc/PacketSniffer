package SnifferScope;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;


public class UpdateTextOutput extends Thread {

    volatile AtomicBoolean running = new AtomicBoolean();
    DefaultTableModel tableModel;
    LinkedBlockingQueue<Packet> packetQueue;
    JTable table;

    public UpdateTextOutput(LinkedBlockingQueue<Packet> packetQueue, DefaultTableModel tableModel, JTable table) {
        this.tableModel = tableModel;
        this.packetQueue = packetQueue;
        this.table = table;
        running.set(true);
    }

    public void StopUpdating() {
        running.set(false);
    }

    @Override
    public void run() {
        int num = 0; // счетчик пакетов
        boolean changed;

        // выполнение потока до тех пор, пока очередь не станет пустой*/
        while (running.get() || !packetQueue.isEmpty()) {
            try {
                changed = false;




                while (!packetQueue.isEmpty()) {
                    if (tableModel.getRowCount() > 10000) { //после 10000 строки удаляется самая первая по циклу*/
                        tableModel.removeRow(0);
                    }

                    // статические пакеты
                    Packet packet = packetQueue.poll();
                    num++;

                    assert packet != null;
                    if (packet.contains(IpV4Packet.class)) {
                        IpV4Packet ip4v = packet.get(IpV4Packet.class); // IPv4

                        if (ip4v.getPayload().contains(DnsPacket.class)) {
                            DnsPacket dns = ip4v.getPayload().get(DnsPacket.class);

                            tableModel.addRow(new Object[] {num,   "DNS", ip4v.getHeader().getSrcAddr(),
                                    ip4v.getHeader().getDstAddr(), dns.toString() });
                        } else if (ip4v.getPayload().contains(IcmpV4CommonPacket.class)) {
                            IcmpV4CommonPacket icmp = ip4v.getPayload().get(IcmpV4CommonPacket.class);

                            tableModel.addRow(new Object[] {num,   "ICMP", ip4v.getHeader().getSrcAddr(),
                                    ip4v.getHeader().getDstAddr(), icmp.toString() });

                        } else {
                            tableModel.addRow(new Object[] {num,   "IPv4", ip4v.getHeader().getSrcAddr(),
                                    ip4v.getHeader().getDstAddr(), ip4v.toString() });
                        }

                    } else if (packet.contains(IpV6Packet.class)) {
                        IpV6Packet ip6v = packet.get(IpV6Packet.class); // Ipv6*/

                        if (ip6v.getPayload().contains(DnsPacket.class)) {
                            DnsPacket dns = ip6v.getPayload().get(DnsPacket.class);

                            tableModel.addRow(new Object[] {num,   "DNS", ip6v.getHeader().getSrcAddr(),
                                    ip6v.getHeader().getDstAddr(), dns.toString() });
                        } else if (ip6v.getPayload().contains(IcmpV4CommonPacket.class)) {
                            IcmpV4CommonPacket icmp = ip6v.getPayload().get(IcmpV4CommonPacket.class);

                            tableModel.addRow(new Object[] {num,   "ICMP", ip6v.getHeader().getSrcAddr(),
                                    ip6v.getHeader().getDstAddr(), icmp.toString() });
                        } else {
                            tableModel.addRow(new Object[] {num,   "IPv6", ip6v.getHeader().getSrcAddr(),
                                    ip6v.getHeader().getDstAddr(), ip6v.toString() });
                        }
                    } else if (packet.contains(ArpPacket.class)) { // ARP низкий уровень пакета, не будет найдет из-за ipv4 ipv6*/
                        ArpPacket arp = packet.get(ArpPacket.class);
                        tableModel.addRow(new Object[] {num,  "ARP", arp.getHeader().getSrcHardwareAddr(),
                                arp.getHeader().getDstHardwareAddr(), arp.toString() });
                    } else {
                       tableModel.addRow(new Object[] {num, "UNKNOWN Type", packet.getHeader(), packet.getHeader(), packet.toString() } );
                    }

                    changed = true;
                }
                if (changed) {
                    table.getParent().revalidate(); // обновляет страницу, на гитхабе посмотреть решение*/
                }
                try {
                    Thread.sleep(250);
                } catch (InterruptedException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            } catch (Exception e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
    }
}
