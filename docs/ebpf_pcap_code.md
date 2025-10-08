# ebpf_pcap 핵심 로직 정리

## ebpf_pcap.c

### c 코드 특징

- `vmlinux.h` 사용
  - linux 관련 전처리기를 `vmlinux.h`로 모두 대체
- ringbuf BPF map `events` 생성
- eBPF 프로그램 함수 `handle_packet` 작성
  - tc hook attach 명시

### `handle_packet` 주요 로직

- L2 패킷 검사
  - 메모리 안전성을 위한 패킷 헤더 크기 확인
- L3 패킷 검사
  - 메모리 안전성을 위한 패킷 헤더 크기 확인
  - IPv4만 처리
- L4 패킷 검사
  - TCP, UDP만 처리
- 패킷 헤더 정보 추출 및 저장
- ringbuf에 패킷 정보 push

### `ringbuf` 구조체

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF); // 타입 지정하기: BPF_MAP_TYPE_RINGBUF
    __uint(max_entries, 1 << 24); // ringbuf 크기 지정하기
} events SEC(".maps");
```

### `SEC("tc")`

```c
SEC("tc")
```

- 해당 프로그램이 tc hook에 부착할 것임을 명시
  - 단순 메타데이터로 실제 hook attach와는 무관
- 실제 ebpf 프로그램의 부착은 go 스크립트에서 이루어짐(`link.AttachTCX()`)
  - ebpf 프로그램의 attach, 실행, 관리는 모두 go가 담당
  - c 코드는 eBPF 프로그램의 로직만을 정의할 뿐임

### `__sk_buff`

```c
int handle_packet(struct __sk_buff *skb) {...}
```

- `__sk_buff`는 커널의 `sk_buff` 구조체를 미러링한 구조체
  - `vmlinux.h`에 포함
  - `__sk_buff` 접근 시 `sk_buff` 접근으로 변환
- 주요 필드로는 len, protocol, data/data_end(패킷 시작-끝 포인터) 등 존재
- 패킷이 네트워크 스택을 통과할 때, 자동으로 필드가 채워짐

## ebpf_pcap.go

### go 코드 특징

- c 구조체 `events`를 go 구조체 `packetEvent`로 수동 정의
- `logFile`(`/var/log/ebpf.log`)에 로그 작성, 이로 인해 `sudo` 권한 필요
- `objs`에 eBPF 객체 로드
- `rd`에 ringbuf map 로드

### `main` 주요 로직

- `logFile` open
- eBPF 객체 `objs`로드
- NIC 조회 및 eBPF 프로그램을 NIC TC hook의 ingress, egress 연결
- ringbuf 리더 `rd` 생성
- goroutine에서 ringbuf 데이터를 꺼내 파싱 후 출력, `logFile` 기록

### eBPF 객체 로드

```go
 objs := ebpf_pcapObjects{}
 if err := loadEbpf_pcapObjects(&objs, nil); err != nil {
  log.Fatalf("eBPF 프로그램 로드 실패: %v", err)
 }
 defer objs.Close()
```

- bpf2go가 자동 생성한 코드를 바탕으로 eBPF 객체 로드
  - `ebpf_pcapObjects` 내에 C 함수 `handle_packet`과 `events` 포함
  - C의 변수/함수명은 PascalCase로 자동 변환됨 (`events` → `Events`, `handle_packet` → `HandlePacket`)

### TC hook attach

```go
// Ingress hook
lIngress, err := link.AttachTCX(link.TCXOptions{
    Interface: iface.Index,
    Program:   objs.HandlePacket,
    Attach:    ebpf.AttachTCXIngress,
})
if err != nil {
    log.Printf("[경고] %s ingress hook 연결 실패: %v", iface.Name, err)
} else {
    links = append(links, lIngress)
    log.Printf("[+] %s ingress hook 연결 성공", iface.Name)
}
```

- C 코드로 작성된 eBPF 프로그램을 hook에 attach, 설정하는 것은 go 코드에서 수행
  - `AttachTCX()`는 eBPF 프로그램을 네트워크 인터페이스의 TC hook에 부착
  - `TCXOptions`로 인터페이스, 프로그램, 방향(ingress/egress)을 지정