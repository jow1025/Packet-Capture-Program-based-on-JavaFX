# Packet-Capture-Program-based-on-JavaFX
JavaFX GUI기반의 패킷캡쳐 프로그램입니다. 오픈 소스 패킷 분석 프로그램인 Wireshak의 기능을 간단하게 구현해보았습니다.

기능: 패킷 캡쳐 시작/중지, 장비선택(네트워크 인터페이스 카드), 필터링(특정 프로토콜), 저장(txt파일)

검출 가능 프로토콜: TCP, UDP, ICMP, HTTP, ARP, IPv4

*DNS 프로토콜은 Jnetpcap에서 구현된 api가 없어서 CMD창에서 Nslookup 명령어를 이용해 UDP프로토콜로 일부 확인할 수 있습니다.
*ICMP 프로토콜은 CMD창에서 Ping 명령어로 확인할 수 있습니다.


<h2><br>환경</h3>
1. OS: Windows10 Home</br>
2. Library: Jnetpcap, WinPcap<br>
3. GUI: JavaFX(Eclipse)</br>

<h2><br>세팅</h3>
1. 윈도우환경에서 사용하기 위해 WinPcap(윈도우용 패킷 캡쳐 아키텍쳐)를 설치합니다.<br>
 https://www.winpcap.org/install/<br>
2. 자바 환경(Eclipse)에서 패킷을 캡쳐하기 위해 JnetPcap을 설치합니다.<br>
https://sourceforge.net/projects/jnetpcap/
3. 압축을 푼 뒤 jnetpcap.dll 파일과 jnetpcap-pcap100.dll 파일을 C:\Windows\System32에 복붙합니다.<br>
4. JavaFX Windows SDK파일을 내려받고, 압축을 풉니다.<br>
https://gluonhq.com/products/javafx/
5. 이클립스의 Marketplace에서 "javafx"를 검색한 뒤 e(fx)eclipse 3.x.0버전을 설치합니다.(현재 3.7.0버전)<br>
6. JavaFX 라이브러리를 import할 차례입니다. 프로젝트 우클릭->Build Path->Add External Achives를 클릭한 뒤 압축 해제한 javafx폴더의 하위 lib폴더의 .jar파일을 모두 import해줍니다. (총 8개의 파일)<br>
7. 이클립스의 상단의 windows배너->preferences 클릭 후 왼쪽 목록에서 Run/Debug-> String Substitution을 클릭 한 후 새 목록을 추가하여 name을 PATH_TO_FX로, value를 javafx폴더의 lib폴더 경로를 지정해준 뒤 Apply해줍니다.<br>
8. 실행 프로젝트 우클릭-> Properties->Run/Debug Settings클릭 후 Launch configurations for '프로젝트 명" 아래에 뜨는 Main을 더블클릭 후 VM arguments에 아래 내용을 추가한 뒤 apply합니다.<br><br>
<b>--module-path ${PATH_TO_FX} --add-modules=javafx.controls,javafx.fxml<br>
  
<img src="https://user-images.githubusercontent.com/67903177/132000832-7c412f5a-fc74-4e3f-8c27-78a54dec5af2.PNG" width="500" height="450"/>


  





