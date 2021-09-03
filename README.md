# Packet-Capture-Program-based-on-JavaFX
JavaFX GUI기반의 패킷캡쳐 프로그램입니다. 오픈 소스 패킷 분석 프로그램인 Wireshak의 기능을 직접 구현해보았습니다.
기능: 패킷 캡쳐 시작/중지, 장비선택(네트워크 카드), 필터링(특정 프로토콜의 패킷 필터), 저장(화면에 뜬 패킷 캡쳐 내용들을 txt파일로 저장)

검출 가능 프로토콜: TCP, UDP, ICMP, HTTP, ARP, IPv4, IPv6, DNS(부분완료, UDP패킷으로 검출됨)
사용 라이브러리: Jnetpcap
GUI: JavaFX(Eclipse)


