package program.WireScope;

import java.io.File;
//import java.net.Inet4Address;
//import java.util.ArrayList;
//import java.util.List;
//import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
//import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.atomic.AtomicBoolean;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
//import org.pcap4j.core.NotOpenException;
//import org.pcap4j.core.PacketListener;
//import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
//import org.pcap4j.core.PcapHandle.TimestampPrecision;
//import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapStat;
//import org.pcap4j.core.Pcaps;
//import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
//import org.pcap4j.util.NifSelector;
//import org.pcap4j.util.Packets;
//import org.pcap4j.util.PropertiesLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//import program.gui.WireScopeMain;

//import javax.swing.*;

public class MonitorThread extends Thread {

    final static Logger logger = LoggerFactory.getLogger(MonitorThread.class);
    LinkedBlockingQueue<Packet> packetQueue;
    PcapNetworkInterface inteface;
    volatile AtomicBoolean running = new AtomicBoolean();
    boolean fileOutput = false;
    File file = null;
    //JButton btnStart, btnStop;


    String filter;

    public MonitorThread(LinkedBlockingQueue<Packet> packetQueue, PcapNetworkInterface inteface, String filter) {
        this.packetQueue = packetQueue;
        this.inteface = inteface;
        this.filter = filter;
        running.set(true);
    }

    /**
    проверка на существование дамп файла + на англ языке
     */
    public void setFileOutput(File file) {
        this.file = file;
        fileOutput = true;
    }

    /**
     * остановка процесса
     */
    public void StopUpdating() {
        running.set(false);
    }

    @Override
    public void run() {
        PcapDumper dumper = null;

        try {
            /** установка максимального размера пакета с таймаутом в 1 секунду */
            final PcapHandle handle = inteface.openLive(65536, PromiscuousMode.PROMISCUOUS, 1000);

            handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

            if (fileOutput) {
                dumper = handle.dumpOpen(file.getAbsolutePath());
            }

            int num = 0; /** объявление переменной для счетчика количества пакетов */
            while (running.get()) {
                Packet packet = handle.getNextPacket();

                if (packet == null) {
                    continue;
                } else {
                    packetQueue.add(packet);

                    if (fileOutput) {
                        dumper.dump(packet, handle.getTimestamp());
                    }

                    logger.debug(handle.getTimestamp().toString());
                    logger.debug(packet.toString());

                    num++;
                    if (num >= 10000) { /** максимальное значение для перехвата количества пакетов */
                      //btnStart.setEnabled(true);
                      //btnStop.setEnabled(false);
                        break;
                    }
                }
            }
/**
 * финальное сообщение после окончания перехвата пакетов
 */
            PcapStat ps = handle.getStats();
            logger.info("Пакетов получено: " + ps.getNumPacketsReceived());
            logger.info("Пакетов потеряно: " + ps.getNumPacketsDropped());
            logger.info("Пакетов потеряно интерфейсом: " + ps.getNumPacketsDroppedByIf());
            if (com.sun.jna.Platform.isWindows()) {
                logger.info("Пакетов захвачено: " + ps.getNumPacketsCaptured());
            }

            if (fileOutput) {
                dumper.close();
            }
            handle.close();

        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

}
