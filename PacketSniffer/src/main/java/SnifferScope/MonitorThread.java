package SnifferScope;

import java.io.File;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;

import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapStat;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MonitorThread extends Thread {

    final static Logger logger = LoggerFactory.getLogger(MonitorThread.class);
    LinkedBlockingQueue<Packet> packetQueue;
    PcapNetworkInterface inteface;
    volatile AtomicBoolean running = new AtomicBoolean();
    boolean fileOutput = false;
    File file = null;
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
            // установка максимального размера пакета с таймаутом в 1 секунду */
            final PcapHandle handle = inteface.openLive(65536, PromiscuousMode.PROMISCUOUS, 1000);

            handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

            if (fileOutput) {
                dumper = handle.dumpOpen(file.getAbsolutePath());
            }

            int num = 0; // объявление переменной для счетчика количества пакетов */
            while (running.get()) {
                Packet packet = handle.getNextPacket();

                if (packet == null) {
                    continue;
                } else {
                    packetQueue.add(packet);

                    if (fileOutput) {
                        assert dumper != null;
                        dumper.dump(packet, handle.getTimestamp());
                    }

                    logger.debug(handle.getTimestamp().toString());
                    logger.debug(packet.toString());

                    num++;
                    if (num >= 2000) { //* максимальное значение для перехвата количества пакетов */
                        break;
                    }
                }
            }
/*
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
                assert dumper != null;
                dumper.close();
            }
            handle.close();

        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

}
