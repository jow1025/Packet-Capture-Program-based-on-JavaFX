package sniffer;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.ResourceBundle;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import com.sun.javafx.scene.control.skin.Utils;

import javafx.application.Platform;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ListChangeListener;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.scene.control.MenuBar;
import javafx.scene.control.MenuItem;
import javafx.scene.control.TextArea;
import javafx.scene.layout.HBox;
import javafx.scene.text.Text;
import javafx.scene.text.TextAlignment;
import javafx.stage.Stage;

public class ControllerMain implements Initializable {
	@FXML
	private MenuBar menuBar;
	@FXML
	private MenuItem fileSave;
	@FXML
	private MenuItem selectInterface;
	@FXML
	private MenuItem startSniffer;
	@FXML
	private MenuItem filters;
	@FXML
	private ListView<PcapPacket> listPackets;//이 리스트로 파일에 담을 데이터관리
	@FXML
	private MenuItem stopSniffer;
	@FXML
	private TextArea dataDump;
	@FXML
	private Label tcpPacket;
	@FXML
	private Label udpPacket;
	@FXML
	private Label totalPacket;
	@FXML
	private Label icmpPacket;
	@FXML
	private Label httpPacket;
	@FXML
	private Label ipv4Packet;
	@FXML
	private Label ipv6Packet;
	@FXML
	private Label arpPacket;

	@FXML
	private Label otherPacket;
	private long tcpN = 0;
	private long udpN = 0;
	private long totalN = 0;
	private long httpN = 0;
	private long arpN = 0;
	private long icmpN = 0;
	private long ipv4N = 0;

	private long ipv6N = 0;
	private long otherN = 0;
	FXMLLoader fxmlLoaderInterface;
	FXMLLoader fxmlLoaderFilter;
	//Interface + Flitter=> 연계
	ControllerInterface CtrlInterf;
	ControllerFilter CtrlFilter;
	Stage stage = null;
	StringBuilder errbuf = new StringBuilder();
	Thread snifferThread = null;
	private PcapIf device = null;
	
	volatile ObservableList<PcapPacket> packets = FXCollections.observableArrayList();
	ObservableList<PcapPacket> packetsShow = FXCollections.observableArrayList();
	boolean http = true;
	boolean icmp = true;
	boolean arp = true;
	boolean tcp = true;
	boolean ip4 = true;
	boolean udp = true;
	boolean ip6 = true;

	@Override
	public void initialize(URL location, ResourceBundle resources) {
		packetsShow.add(new PcapPacket(0));
		//우분투에서는 절대경로로 써야하는데 적용안됬음
		fxmlLoaderInterface = new FXMLLoader(getClass().getResource("interface.fxml"));
		fxmlLoaderFilter = new FXMLLoader(getClass().getResource("filter.fxml"));

		CtrlInterf = fxmlLoaderInterface.getController();
		
		Parent interfaces = null;
		try {
			interfaces = fxmlLoaderInterface.load();
		} catch (IOException e) {
			e.printStackTrace();
		}
		// 장비선택+ 프로토콜 선택 창 문자열 출력
		final Stage stageInterface = new Stage();
		stageInterface.setScene(new Scene(interfaces));
		stageInterface.setTitle("네트워크 장비 선택");
		
		Parent filter = null;
		try {
			filter = fxmlLoaderFilter.load();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		final Stage stageFilter = new Stage();
		stageFilter.setScene(new Scene(filter));
		stageFilter.setTitle("프로토콜 선택");
		CtrlFilter = fxmlLoaderFilter.getController();
		
		CtrlFilter.setMainController(this);
		
		//리스너-> 총계 표현
		packets.addListener((ListChangeListener<PcapPacket>) c -> {
			PcapPacket item = packets.get(packets.size() - 1);
			
			Platform.runLater(new Runnable() {
				@Override
				public void run() {
					
					tcpPacket.setText("" + tcpN);
					udpPacket.setText("" + udpN);
					totalPacket.setText("" + totalN);
					icmpPacket.setText("" + icmpN);
					arpPacket.setText("" + arpN);
					httpPacket.setText("" + httpN);
					ipv4Packet.setText("" + ipv4N);
					ipv6Packet.setText("" + ipv6N);

					otherPacket.setText(totalN - tcpN - udpN - icmpN - ipv4N - ipv6N - arpN - httpN + "");

				}
			});

			synchronized (this) {
				//계속 동적으로 진행되어야 됨 
				if (http && item.hasHeader(new Http())) {
					totalN++;
					httpN++;
					packetsShow.add(item);

					return;
				}
				if (icmp && item.hasHeader(new Icmp())) {
					totalN++;
					icmpN++;
					packetsShow.add(item);
					return;
				}
				if (tcp && item.hasHeader(new Tcp())) {
					totalN++;
					tcpN++;
					packetsShow.add(item);
					return;
				}
				if (udp && item.hasHeader(new Udp())) {
					totalN++;
					udpN++;
					packetsShow.add(item);

					return;
				}

				if (ip4 && item.hasHeader(new Ip4())) {
					totalN++;
					ipv4N++;
					packetsShow.add(item);
					return;
				}
				if (ip6 && item.hasHeader(new Ip6())) {
					totalN++;
					ipv6N++;
					packetsShow.add(item);
					return;
				}
				if (arp && item.hasHeader(new Arp())) {
					totalN++;
					arpN++;
					packetsShow.add(item);
				}

			} 

		});
			
		listPackets.setItems(packetsShow);
		listPackets.setCellFactory((ListView<PcapPacket> item) -> new packetCell());
		//모델 선택 리스너-> 아래 창에 출력
		listPackets.getSelectionModel().selectedItemProperty().addListener(new ChangeListener<PcapPacket>() {
			@Override
			public void changed(ObservableValue<? extends PcapPacket> observable, PcapPacket oldValue,
					PcapPacket newValue) {
				if (packetsShow.indexOf(newValue) == 0) {
					return;
				}
				
				dataDump.setText(newValue.toString());// 정렬안된 데이터들
				// toHexDump() -> 페이로드만

			}
		});
		
		selectInterface.setOnAction(new EventHandler<javafx.event.ActionEvent>() {
			@Override
			public void handle(javafx.event.ActionEvent event) {
				stageInterface.show();
			}
		});
		filters.setOnAction(new EventHandler<javafx.event.ActionEvent>() {
			@Override
			public void handle(javafx.event.ActionEvent event) {
				stageFilter.show();
			}
		});
		
		stopSniffer.setOnAction(new EventHandler<ActionEvent>() {
			@Override
			public void handle(ActionEvent event) {

				if (snifferThread != null) {
					snifferThread.stop();
					snifferThread = null;
					// System.out.println("stop sniffer");
				}
			}
		});
		startSniffer.setOnAction(new EventHandler<javafx.event.ActionEvent>() {
			@Override
			public void handle(javafx.event.ActionEvent event) {
				CtrlInterf = fxmlLoaderInterface.getController();
				//네트워크 장치 오류: 없거나 잘못됬거나 동작이 없는 네트워크 카드거나
				if (CtrlInterf == null || CtrlInterf.getInterface() == null) {
					Alert DevNotSelected = new Alert(Alert.AlertType.WARNING);
					DevNotSelected.setTitle("잘못된 네트워크장비임");
					DevNotSelected.setHeaderText("네트워크 장비선택바람！");
					DevNotSelected.setContentText("네트워크장비가 없거나 잘못된 장비！");
					DevNotSelected.show();
				} else {
					snifferThread = new Thread(() -> {
						
						device = CtrlInterf.getInterface();
						
						int snaplen = 64 * 1024; //pcap에서는 최대 65535
						int flags = Pcap.MODE_PROMISCUOUS;//혼잡모드 
						int timeout = 30 * 1000;// 시간 관리. 이렇게 해놔도 매우많이 쏟아짐
						
						Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
						if (pcap == null) {
							System.out.println("Error while opening device for capture." + errbuf);
						}
						
						PcapPacketHandler<String> pcapPacketHandler = new PcapPacketHandler<String>() {
							@Override
							public void nextPacket(PcapPacket pcapPacket, String s) {
								
								packets.add(pcapPacket);
								
							}
						};
						
						pcap.loop(-1, pcapPacketHandler, "Jnetpcap rocks");
						// System.out.println(device.toString());
					});
					snifferThread.start();
				}
			}
		});
		// 
		fileSave.setOnAction(new EventHandler<ActionEvent>() {
			@Override
			public void handle(ActionEvent event) {
				// TODO Auto-generated method stub
				int result = writeIntoFile(packets);
				if (result == 0) {
					Alert DevNotSelected = new Alert(Alert.AlertType.INFORMATION);
					//파일 저장 폴더. 폴더는 만들어놔야함
					DevNotSelected.setContentText("C:\\MyCapturePacket");
					DevNotSelected.show();
				} else {
					Alert DevNotSelected = new Alert(Alert.AlertType.INFORMATION);
					DevNotSelected.setContentText("파일저장실패");
					DevNotSelected.show();
				}
			}
		});
	}

	public synchronized void filterChanged() {
		System.out.println("update list.");
		packetsShow.clear();
		packetsShow.add(new PcapPacket(0));
		http = CtrlFilter.isHttp();
		arp = CtrlFilter.isArp();
		icmp = CtrlFilter.isIcmp();
		tcp = CtrlFilter.isTcp();
		udp = CtrlFilter.isUdp();
		ip4 = CtrlFilter.isIp4();
		ip6 = CtrlFilter.isIp6();
		tcpN = 0;
		udpN = 0;
		totalN = 0;
		icmpN = 0;
		httpN = 0;
		ipv4N = 0;
		ipv6N = 0;
		arpN = 0;
		otherN = 0;
		if (packets.size() == 0) {
			return;
		}
		
		for (PcapPacket item : packets) {
			if (http && item.hasHeader(new Http())) {
				httpN++;
				totalN++;
				packetsShow.add(item);
				continue;
			}
			if (icmp && item.hasHeader(new Icmp())) {
				icmpN++;
				totalN++;
				packetsShow.add(item);
				continue;
			}
			if (tcp && item.hasHeader(new Tcp())) {
				tcpN++;
				totalN++;
				packetsShow.add(item);
				continue;
			}
			if (udp && item.hasHeader(new Udp())) {
				udpN++;
				totalN++;
				packetsShow.add(item);
				continue;
			}
			if (ip4 && item.hasHeader(new Ip4())) {
				ipv4N++;
				totalN++;
				packetsShow.add(item);
				continue;
			}
			if (ip6 && item.hasHeader(new Ip6())) {
				ipv6N++;
				totalN++;
				packetsShow.add(item);
				continue;
			}
			if (arp && item.hasHeader(new Arp())) {
				arpN++;
				totalN++;
				packetsShow.add(item);
			}
		}
		
		Platform.runLater(() -> {
			icmpPacket.setText("" + icmpN);
			arpPacket.setText("" + arpN);
			tcpPacket.setText("" + tcpN);
			udpPacket.setText("" + udpN);
			totalPacket.setText("" + totalN);
			httpPacket.setText(httpN + "");
			ipv4Packet.setText("" + ipv4N);
			ipv6Packet.setText(" " + ipv6N + " ");
			otherPacket.setText(totalN - tcpN - udpN - ipv4N - icmpN - ipv6N - arpN - httpN + "");
		});
	}

	class packetCell extends ListCell<PcapPacket> {
		@Override
		synchronized protected void updateItem(PcapPacket item, boolean empty) {
			super.updateItem(item, empty);
			Platform.runLater(() -> {
				setGraphic(null);
				setText(null);
				// System.out.println(packetsShow.indexOf(item));
				if (item != null && packetsShow.indexOf(item) == 0) {
					HBox hBox = new HBox();
					Text id = new Text("넘버");
					id.setWrappingWidth(30);
					id.setTextAlignment(TextAlignment.CENTER);
					Text srcIP = new Text("소스ip주소");
					srcIP.setWrappingWidth(95);
					srcIP.setTextAlignment(TextAlignment.CENTER);
					Text dstIP = new Text("목적지ip주소");
					dstIP.setWrappingWidth(95);
					dstIP.setTextAlignment(TextAlignment.CENTER);
					Text srcMac = new Text("소스MAC주소");
					srcMac.setWrappingWidth(110);
					srcMac.setTextAlignment(TextAlignment.CENTER);
					Text dstMac = new Text("목적지MAC주소");
					dstMac.setWrappingWidth(110);
					dstMac.setTextAlignment(TextAlignment.CENTER);
					Text length = new Text("길이");
					length.setWrappingWidth(50);
					length.setTextAlignment(TextAlignment.CENTER);
					Text prot = new Text("프로토콜");
					prot.setWrappingWidth(50);
					prot.setTextAlignment(TextAlignment.CENTER);
					Text time = new Text("시간");
					time.setWrappingWidth(80);
					time.setTextAlignment(TextAlignment.CENTER);
					hBox.getChildren().addAll(id, srcIP, dstIP, srcMac, dstMac, length, prot, time);
					setGraphic(hBox);
				} else {
					if (item != null) {
						
						Ethernet eth = new Ethernet();
						Ip4 ip4 = new Ip4();
						item.hasHeader(ip4);
						item.hasHeader(eth);
						HBox hBox = new HBox();
						
						Text id = new Text("" + packetsShow.indexOf(item));
						id.setWrappingWidth(30);
						id.setTextAlignment(TextAlignment.CENTER);
						
						Text srcIP;
						try {
							srcIP = new Text(FormatUtils.ip(ip4.source()));
						} catch (NullPointerException e) {
							srcIP = new Text("---.---.---.---");
						}
						srcIP.setWrappingWidth(95);
						srcIP.setTextAlignment(TextAlignment.CENTER);
						//잘못된 정보는 따로 구분시켜줘야함
						Text dstIP;
						try {
							dstIP = new Text(FormatUtils.ip(ip4.destination()));
						} catch (NullPointerException e) {
							dstIP = new Text("---.---.---.---");
						}
						dstIP.setWrappingWidth(95);
						dstIP.setTextAlignment(TextAlignment.CENTER);
						//Mac
						Text srcMac = new Text(FormatUtils.mac(eth.source()));
						srcMac.setWrappingWidth(110);
						srcMac.setTextAlignment(TextAlignment.CENTER);
						//목적지 MAC
						Text dstMac = new Text(FormatUtils.mac(eth.destination()));
						dstMac.setWrappingWidth(110);
						dstMac.setTextAlignment(TextAlignment.CENTER);
						// 길이
						Text length = new Text("" + item.getCaptureHeader().wirelen());
						length.setWrappingWidth(30);
						length.setTextAlignment(TextAlignment.CENTER);
						String protocol = null;
						// 
						if (item.hasHeader(new Arp())) {
							protocol = "ARP";
						}
						if (item.hasHeader(new Ip4())) {
							protocol = "IPv4";
						} else if (item.hasHeader(new Ip6())) {
							protocol = "IPv6";
						}
						if (item.hasHeader(new Udp())) {
							protocol = "UDP";
						}
						if (item.hasHeader(new Tcp())) {
							protocol = "TCP";
						}
						if (item.hasHeader(new Icmp())) {
							protocol = "ICMP";
						}

						if (item.hasHeader(new Http())) {
							protocol = "HTTP";
						}
						Text prot = new Text(protocol);
						prot.setWrappingWidth(40);
						prot.setTextAlignment(TextAlignment.CENTER);
						//캡쳐 시각
						Text time = new Text(
								new SimpleDateFormat("HH:mm:ss").format(item.getCaptureHeader().timestampInMillis()));
						time.setWrappingWidth(80);
						time.setTextAlignment(TextAlignment.CENTER);
						// AddALL-> 모든 데이터출력
						hBox.getChildren().addAll(id, srcIP, dstIP, srcMac, dstMac, length, prot, time);
						setGraphic(hBox);
					}
				}
			});
		}

	}

	public int writeIntoFile(ObservableList<PcapPacket> packets) {
		Date date = new Date();
		SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
		String nowTime = format.format(date);
		System.out.println(nowTime);
		// 
		File outPutDir = new File("C:\\MyCapturePacket");
		if (!outPutDir.exists()) {
			outPutDir.mkdirs();
		}
		nowTime = nowTime.replaceAll(":", ".");
		File outPutFile = new File("C:\\MyCapturePacket\\" + nowTime + ".txt");
		if (!outPutFile.exists()) {
			try {
				outPutFile.createNewFile();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		try {
			PrintWriter pw = new PrintWriter(outPutFile);
			List<DataPackageModel> list = new ArrayList<DataPackageModel>();
			List<String>list2=new ArrayList<String>();
			int count = 0;

			
			for (PcapPacket packet : packets) {

				Ethernet eth = new Ethernet();
				Ip4 ip4 = new Ip4();
				packet.hasHeader(ip4);
				packet.hasHeader(eth);
				//정의한 클래스 객체로 리스트에 저장할 데이터를 담음
				DataPackageModel model = new DataPackageModel();
				model.setId("" + (++count));
				String srcIp;
				String desIp;
				String protocol;
				try {
					srcIp = new String(FormatUtils.ip(ip4.source()));

				} catch (Exception e) {
					// TODO: handle exception
					srcIp = "---.---.---.---";
				}
				try {
					desIp = new String(FormatUtils.ip(ip4.destination()));
				} catch (Exception e) {
					// TODO: handle exception
					desIp = "---.---.---.---";
				}
				model.setSrcIp(srcIp);
				model.setDesIp(desIp);

				model.setSrcMac(new String(FormatUtils.mac(eth.source())));
				model.setDesMac(new String(FormatUtils.mac(eth.destination())));
				model.setLength(packet.getCaptureHeader().wirelen() + "");
				// 
				model.setProtocol(judgePro(packet));
				model.setTime(new SimpleDateFormat("HH:mm:ss").format(packet.getCaptureHeader().timestampInMillis()));
				model.setContent(packet.toHexdump());

				list.add(model);
				
		
             
				list2.add(packet.toString());//로우
				list2.add("------------\n");
				list2.add(packet.toHexdump());//페이로드
		           
				list2.add("------------\n");	
			}
			
			for(String a:list2)
			{
				if(a.contains("*******")) {
					pw.println();
					//정규 표현식으로 무분별하게 쏟아진 로우 데이터를 정렬시켜줌
				pw.print(a.replaceAll("------------\n([^:\n]*):[ ]*[*]{6,}[ ]*([^\n]*)", "----1------$2\n-----2-----")
		                .replaceAll("<h1>([^<]*)-?[ ]*(offset[^<]*)</h1>", "$1$2")
		                .replaceAll("Data:[ ]*\n", "")
		                .replaceAll("([^:\n]*):[ ]*\n", "")//추가해도안뜸
		                .replaceAll("([^:\n ]*):[ ]+([^=\n<>]+)=([^\n<>]+)\n", "$2$3\n")///zzz자리.
		                .replaceAll("[^:\n]*:[\n ]*</table>", ""));//추가해도안뜸);
				}
				else {
					pw.print(a.replaceAll("------------\n([^:\n]*):[ ]*[*]{6,}[ ]*([^\n]*)", "----1------$2\n-----2-----")
			                .replaceAll("<h1>([^<]*)-?[ ]*(offset[^<]*)</h1>", "$1$2")
			                .replaceAll("Data:[ ]*\n", "")
			                .replaceAll("([^:\n]*):[ ]*\n", "")//추가해도안뜸
			                .replaceAll("([^:\n ]*):[ ]+([^=\n<>]+)=([^\n<>]+)\n", "$2$3\n")///zzz자리.
			                .replaceAll("[^:\n]*:[\n ]*</table>", ""));//추가해도안뜸);
				
				pw.println();
				}
			}
			pw.flush();
			pw.close();
//			for (DataPackageModel model : list) {
//
//				pw.print(model);
//				pw.println();
//				pw.println("--------------------------------");
//				pw.println("--------------------------------");
//				pw.println("--------------------------------");
//			}
//			pw.flush();
//			pw.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return -1;
		}
		return 0;
	}

	public String judgePro(PcapPacket item) {
		String protocol = null;
		// 
		if (item.hasHeader(new Arp())) {
			protocol = "ARP";
		}
		if (item.hasHeader(new Ip4())) {
			protocol = "IPv4";
		} else if (item.hasHeader(new Ip6())) {
			protocol = "IPv6";
		}
		if (item.hasHeader(new Udp())) {
			protocol = "UDP";
		}
		if (item.hasHeader(new Tcp())) {
			protocol = "TCP";
		}
		if (item.hasHeader(new Icmp())) {
			protocol = "ICMP";
		}

		if (item.hasHeader(new Http())) {
			protocol = "HTTP";
		}
		return protocol;
	}
}
