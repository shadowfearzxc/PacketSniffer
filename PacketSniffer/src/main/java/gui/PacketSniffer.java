package gui;

import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;

import SnifferScope.MonitorThread;
import SnifferScope.UpdateTextOutput;

public class PacketSniffer {



    final static Logger logger = LoggerFactory.getLogger(PacketSniffer.class);
    private List<PcapNetworkInterface> interfaces;
    private JFrame frame;

    private JTextField txtFilters;
    private JComboBox ddlInterfaces;
    private MonitorThread monitorThread;
    private UpdateTextOutput updateTextOutputThread;
    /**
     * выводы
     */
    //private boolean running;
    JPanel pnlData;
    JButton btnStart, btnStop;
    /**
     * кнопки старт-стоп
     */
    JCheckBox chkBoxDumpFile;
    /**
     * чекбокс на включение дампа файлов
     */
    JLabel lblFilePath = new JLabel("");


    JTextArea txtData;

    private JTable tblOutput;
    private DefaultTableModel tableModel;

    /**
     * Запуск приложения.
     */
    public static void main(String[] args) {
        EventQueue.invokeLater(() -> {
            try {
                PacketSniffer window = new PacketSniffer(); // основной интерфейс */
                window.frame.setVisible(true); //* включение-выключение отображения интерфейса, если false - не работает */
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }

    /**
     * Создание приложения
     */
    public PacketSniffer() { // поиск всех возможный адаптеров и их вывод, работает библиотека pcap4j */
        initialize();
        try {
            interfaces = org.pcap4j.core.Pcaps.findAllDevs();
            populateInterfaceList();
        } catch (PcapNativeException e) {
            //TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private void populateInterfaceList() { //* вывод в консоль список адаптеров */
        for (PcapNetworkInterface inFace : interfaces) {
            ddlInterfaces.addItem(new ComboItem(inFace.getDescription(), inFace.getName()));
            logger.info("Адаптер: " + inFace.getDescription());
        }
    }

    private void StartMonitoring() { // после запуска, выводит IP адрес исполнительного адаптера */
        LinkedBlockingQueue<Packet> packetQueue = new LinkedBlockingQueue<Packet>();

        try {
            PcapNetworkInterface inteface = interfaces.get(ddlInterfaces.getSelectedIndex());

            for (PcapAddress addr : inteface.getAddresses()) {
                if (addr.getAddress() != null) { //* сам вывод адреса исполнительного адаптера */
                    logger.info("IP адрес: " + addr.getAddress());
                }
            }

            monitorThread = new MonitorThread(packetQueue, inteface, txtFilters.getText());

            if (chkBoxDumpFile.isSelected()) { //* если нажали на кнопку дамп файл ВКЛЮЧИТЬ, открытие окна выбора файла */
                File file = new File(lblFilePath.getText());
                monitorThread.setFileOutput(file);
            }

            monitorThread.start(); //* старт поиска пакетов */

            updateTextOutputThread = new UpdateTextOutput(packetQueue, tableModel, tblOutput);
            updateTextOutputThread.start();
            btnStart.setEnabled(false); //* выключение кнопки старта */
            btnStop.setEnabled(true); //* включение кнопки стоп */

        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

    /**
     * Инициализация фрейма
     */
    private void initialize() {
        frame = new JFrame();
        frame.setTitle("PacketSniffer v1.0.11");
        frame.setBounds(100, 100, 708, 496); //* выставление начальных размеров окна */
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE); // операция закрытия */
        frame.getContentPane().setLayout(new BorderLayout(0, 0)); // панель содержимого */
// gitgub interface JPanel*/
        JPanel pnlSide = new JPanel(); // объявление панели 1  для интерфейса. */
        pnlSide.setLayout(new BoxLayout(pnlSide, BoxLayout.Y_AXIS)); // выстраивание панелей по Y (вертикаль) */

        JPanel panel_1 = new JPanel(); // объявление панели 2 для интерфеса */
        pnlSide.add(panel_1);
        panel_1.setLayout(new BoxLayout(panel_1, BoxLayout.X_AXIS)); //* выставление списка адаптеров под кнопками с макетом */

        btnStart = new JButton("\u25B6");           //*значок стрелочки */
        btnStart.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                StartMonitoring(); // запуск функции для перехвата пакетов */
            }
        });
        panel_1.add(btnStart); //* добавление кнопки старт в панель */
        btnStart.setForeground(new Color(0, 128, 0));

        btnStop = new JButton("\u25A0");        // значок стоп*/
        btnStop.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {

                monitorThread.StopUpdating(); //* запуск функции останавливающая весь процесс перехвата пакетов
               //  вывод сообщения с информацией о записи/потери пакетов
                // кнопка старт активируется - кнопка стоп деактивация */
                updateTextOutputThread.StopUpdating();
                btnStart.setEnabled(true);
                btnStop.setEnabled(false);
            }
        });
        btnStop.setEnabled(false); // первоначальное состояние кнопки - выключено */

        panel_1.add(btnStop);
        btnStop.setForeground(new Color(255, 0, 0));

        JPanel panel_2 = new JPanel(); // создание окошка для выбора доступных адаптеров */
        pnlSide.add(panel_2);
        panel_2.setLayout(new FlowLayout(FlowLayout.LEADING, 5, 5));

        JLabel lblInterface = new JLabel("Адаптеры: ");
        panel_2.add(lblInterface);

        ddlInterfaces = new JComboBox(); //* совмещение панелей */
        panel_2.add(ddlInterfaces);

        JPanel panel_3 = new JPanel(); //* не работает */
        pnlSide.add(panel_3);

        { //*фильтры
         //P.S. сайт синтаксисов фильтров для работы с библиотекой
         //http://biot.com/capstats/bpf.html*/
            JLabel lblArguments = new JLabel("Фильтры");
             panel_3.add(lblArguments);
            txtFilters = new JTextField();
             panel_3.add(txtFilters); // окно для ввода фильтров
            txtFilters.setColumns(10);
        }

        JPanel panel_4 = new JPanel(); // создание панели для кнопки дамп файлов */
        pnlSide.add(panel_4);

        chkBoxDumpFile = new JCheckBox("Enable");
        //* выбор дамп файла */

        JPanel panel_5 = new JPanel();
        pnlSide.add(panel_5);
        panel_5.setLayout(new FlowLayout(FlowLayout.LEADING, 5, 5));

        JLabel version = new JLabel("version : 1.2.5");
        panel_5.add(version);


        chkBoxDumpFile.addActionListener(arg0 -> {
            if (chkBoxDumpFile.isSelected()) {
                JFileChooser chooser = new JFileChooser();
                FileNameExtensionFilter filter = new FileNameExtensionFilter("pcap file", ".pcap");

                chooser.setFileFilter(filter);
                int returnVal = chooser.showSaveDialog(frame);
                if (returnVal == JFileChooser.APPROVE_OPTION) {
                    lblFilePath.setText(chooser.getSelectedFile().getAbsolutePath());
                    if (!lblFilePath.getText().endsWith(".pcap")) {
                        lblFilePath.setText(lblFilePath.getText() + ".pcap");
                    }
                } else if (returnVal == JFileChooser.CANCEL_OPTION) {
                    chkBoxDumpFile.setSelected(false);
                    lblFilePath.setText("");
                }
            } else {
                lblFilePath.setText("");
                return;
            }
        });

        panel_4.setLayout(new FlowLayout(FlowLayout.CENTER, 5, 5));

        JLabel lblDmp = new JLabel("Dump File");
        panel_4.add(lblDmp);
        panel_4.add(chkBoxDumpFile); // чекбокс */
        frame.getContentPane().add(pnlSide, BorderLayout.WEST);




        JPanel panel = new JPanel();

        pnlSide.add(panel);

        JPanel pnlCenter = new JPanel();
        frame.getContentPane().add(pnlCenter, BorderLayout.CENTER);
        pnlCenter.setLayout(new BorderLayout(0, 0));

        tableModel = new DefaultTableModel( //* вывод колонок с дальнейшим записыванием информации */
                new Object[][]{
                },
                new String[]{
                        "Number", "Type", "Src", "Dst", "Data"
                }
        );
        // вывод колонок*/
        tblOutput = new JTable();
        tblOutput.addMouseListener(new MouseAdapter() {

            public void mouseClicked(MouseEvent arg0) {
                int row = tblOutput.rowAtPoint(arg0.getPoint());
                int col = tblOutput.columnAtPoint(arg0.getPoint());
                if (row >= 0 && col >= 0) {
                    String data = tableModel.getValueAt(tblOutput.getSelectedRow(), 3).toString();
                    txtData.setText(data);
                    pnlData.setVisible(true);
                }
            }
        });
        //* отображение горизонтальных линий разделяющих панель вывода логов пакетов */
        tblOutput.setModel(tableModel);
        tblOutput.setShowHorizontalLines(true);
        JScrollPane scrollPane = new JScrollPane(tblOutput);
        pnlCenter.add(scrollPane, BorderLayout.CENTER);
// клик мышкой по пакету, выдает информацию*/
        pnlData = new JPanel();
        pnlCenter.add(pnlData, BorderLayout.SOUTH);
        pnlData.setLayout(new BorderLayout(0, 0));

        txtData = new JTextArea();
        pnlData.add(txtData, BorderLayout.CENTER);

        JButton btnCloseData = new JButton("Clear"); //* кнопка clear позволяет очистить колонки*/
        btnCloseData.addMouseListener(new MouseAdapter() {

            public void mousePressed(MouseEvent arg0) {

                if (tableModel.getRowCount() > 0) {
                    tableModel.setRowCount(0);
                } else {
                    JOptionPane.showMessageDialog(null, "Очищать нечего. Колонки и так пустые");
                }


            }
        });
        pnlData.add(btnCloseData, BorderLayout.EAST);
        pnlData.setVisible(true);
        frame.getContentPane().add(lblFilePath, BorderLayout.SOUTH);

    }

}
