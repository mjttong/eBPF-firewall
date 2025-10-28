package bpf

import (
	"ebpf-firewall/pkg/rule"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux ebpf_fw ebpf_fw.c

const MaxRules = 30
const stateFilePath = "/var/run/ebpfw.state"
const bpfMountPoint = "/sys/fs/bpf"

var (
	objs       ebpf_fwObjects
	program    *ebpf.Program
	links      []link.Link
	isAttached bool = false
)

// BPF 파일시스템 마운트 확인 및 자동 마운트
func ensureBPFFS() error {
	// 이미 마운트되어 있는지 확인
	var stat unix.Statfs_t
	if err := unix.Statfs(bpfMountPoint, &stat); err == nil {
		// BPF 파일시스템의 매직 넘버: 0xcafe4a11
		if stat.Type == 0xcafe4a11 {
			return nil // 이미 마운트됨
		}
	}

	// 디렉토리 생성 (없을 경우)
	if err := os.MkdirAll(bpfMountPoint, 0755); err != nil {
		return fmt.Errorf("BPF 마운트 포인트 생성 실패: %w", err)
	}

	// BPF 파일시스템 마운트
	if err := unix.Mount("bpffs", bpfMountPoint, "bpf", 0, ""); err != nil {
		// 이미 마운트되어 있으면 EBUSY 에러 발생 (무시)
		if err != unix.EBUSY {
			return fmt.Errorf("BPF 파일시스템 마운트 실패: %w\n힌트: 'sudo mount -t bpf bpffs /sys/fs/bpf'를 수동으로 실행해보세요", err)
		}
	} else {
		log.Printf("[+] BPF 파일시스템을 %s에 마운트했습니다", bpfMountPoint)
	}

	return nil
}

// eBPF 프로그램 로드 및 TC에 연결
func LoadAndAttach() error {
	if isAttached {
		return fmt.Errorf("방화벽이 이미 활성화되어 있습니다")
	}

	if err := ensureBPFFS(); err != nil {
		return err
	}

	if err := loadEbpf_fwObjects(&objs, nil); err != nil {
		return fmt.Errorf("eBPF 프로그램 로드 실패: %w", err)
	}

	// Map을 파일시스템에 pin
	pinPath := "/sys/fs/bpf/ebpfw_rules"
	os.Remove(pinPath)
	if err := objs.RulesArray.Pin(pinPath); err != nil {
		objs.Close()
		return fmt.Errorf("Map pin 실패: %w", err)
	}

	// DefaultPolicy Map pin
	policyPinPath := "/sys/fs/bpf/ebpfw_policy"
	os.Remove(policyPinPath)
	if err := objs.DefaultPolicy.Pin(policyPinPath); err != nil {
		objs.Close()
		return fmt.Errorf("Policy map pin 실패: %w", err)
	}

	program = objs.FirewallFilter

	ifaces, err := net.Interfaces()
	if err != nil {
		objs.Close()
		return fmt.Errorf("네트워크 인터페이스 조회 실패: %w", err)
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		lIngress, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   program,
			Attach:    ebpf.AttachTCXIngress,
		})
		if err != nil {
			log.Printf("[경고] %s ingress hook 연결 실패: %v", iface.Name, err)
		} else {
			links = append(links, lIngress)
			log.Printf("[+] %s ingress hook 연결 성공", iface.Name)
		}

		lEgress, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   program,
			Attach:    ebpf.AttachTCXEgress,
		})
		if err != nil {
			log.Printf("[경고] %s egress hook 연결 실패: %v", iface.Name, err)
		} else {
			links = append(links, lEgress)
			log.Printf("[+] %s egress hook 연결 성공", iface.Name)
		}
	}

	if len(links) == 0 {
		objs.Close()
		return fmt.Errorf("어떤 인터페이스에도 연결할 수 없습니다")
	}

	isAttached = true

	// 상태 파일 생성
	if err := os.WriteFile(stateFilePath, []byte("active"), 0644); err != nil {
		log.Printf("[경고] 상태 파일 생성 실패: %v", err)
	}

	return nil
}

// eBPF 프로그램 분리 및 언로드
func Detach() error {
	if !IsActive() {
		return fmt.Errorf("방화벽이 활성화되어 있지 않습니다")
	}

	// objs 로드 시도 (로드 안되어도 계속 진행)
	_ = ensureObjsLoaded()

	fmt.Println("[!] Detaching eBPF programs from interfaces...")

	// links Close
	for _, l := range links {
		if l != nil {
			l.Close()
		}
	}
	links = nil
	fmt.Println("[!] All interfaces detached.")

	// RulesArray unpin
	pinPath := "/sys/fs/bpf/ebpfw_rules"
	if objs.RulesArray != nil {
		if err := objs.RulesArray.Unpin(); err != nil {
			log.Printf("[경고] Rules map unpin 실패: %v", err)
		}
	}
	os.Remove(pinPath)

	// DefaultPolicy unpin
	policyPinPath := "/sys/fs/bpf/ebpfw_policy"
	if objs.DefaultPolicy != nil {
		if err := objs.DefaultPolicy.Unpin(); err != nil {
			log.Printf("[경고] Policy map unpin 실패: %v", err)
		}
	}
	os.Remove(policyPinPath)

	// 상태 파일 삭제
	os.Remove(stateFilePath)

	// objs Close
	if objs.FirewallFilter != nil {
		objs.Close()
	}

	isAttached = false
	program = nil

	return nil
}

// 방화벽 상태 확인
func IsActive() bool {
	if isAttached {
		return true
	}

	_, err := os.Stat(stateFilePath)
	return err == nil
}

// objs 로드 확인 및 필요시 재로드 (새로운 헬퍼 함수)
func ensureObjsLoaded() error {
	// 이미 로드되어 있으면 OK
	if isAttached && objs.FirewallFilter != nil {
		return nil
	}

	// 상태 파일이 있으면 objs 재로드
	if _, err := os.Stat(stateFilePath); err == nil {
		// objs가 비어있으면 Map 재로드
		if objs.RulesArray == nil {
			pinPath := "/sys/fs/bpf/ebpfw_rules"

			// Pinned Map 로드 (기존 Map 재사용!)
			pinnedMap, err := ebpf.LoadPinnedMap(pinPath, nil)
			if err != nil {
				return fmt.Errorf("Pinned Map 로드 실패: %w", err)
			}

			// objs에 할당
			objs.RulesArray = pinnedMap
		}

		// DefaultPolicy 로드 (추가!)
		if objs.DefaultPolicy == nil {
			policyPinPath := "/sys/fs/bpf/ebpfw_policy"
			pinnedPolicy, err := ebpf.LoadPinnedMap(policyPinPath, nil)
			if err != nil {
				return fmt.Errorf("Pinned Policy Map 로드 실패: %w", err)
			}
			objs.DefaultPolicy = pinnedPolicy
		}
		return nil
	}

	return fmt.Errorf("방화벽이 활성화되어 있지 않습니다")
}

// 단일 규칙 업데이트
func UpdateRule(index uint32, r *rule.Rule) error {
	if err := ensureObjsLoaded(); err != nil {
		return err
	}

	cRule := ebpf_fwFirewallRule{
		SrcIp:     r.SrcIP,
		DstIp:     r.DstIP,
		Port:      r.Port,
		Protocol:  uint8(r.Protocol),
		Direction: uint8(r.Direction),
		Action:    uint8(r.Action),
		Valid:     1,
	}

	return objs.RulesArray.Put(index, cRule)
}

// 규칙 삭제 (무효화)
func DeleteRule(index uint32) error {
	if err := ensureObjsLoaded(); err != nil {
		return err
	}

	cRule := ebpf_fwFirewallRule{
		Valid: 0,
	}

	return objs.RulesArray.Put(index, cRule)
}

// 모든 규칙 동기화
func SyncAllRules(rules []rule.Rule) error {
	if err := ensureObjsLoaded(); err != nil {
		return err
	}

	emptyRule := ebpf_fwFirewallRule{Valid: 0}
	for i := uint32(0); i < MaxRules; i++ {
		if err := objs.RulesArray.Put(i, emptyRule); err != nil {
			return fmt.Errorf("규칙 초기화 실패 (index %d): %w", i, err)
		}
	}

	for i, r := range rules {
		if err := UpdateRule(uint32(i), &r); err != nil {
			return fmt.Errorf("규칙 동기화 실패 (index %d): %w", i, err)
		}
	}

	return nil
}

// 모든 규칙 삭제
func ClearAllRules() error {
	if err := ensureObjsLoaded(); err != nil {
		return err
	}

	emptyRule := ebpf_fwFirewallRule{Valid: 0}
	for i := uint32(0); i < MaxRules; i++ {
		if err := objs.RulesArray.Put(i, emptyRule); err != nil {
			return fmt.Errorf("규칙 삭제 실패 (index %d): %w", i, err)
		}
	}

	return nil
}

// 기본 정책 설정
func SetDefaultPolicy(direction rule.Direction, action rule.Action) error {
	if err := ensureObjsLoaded(); err != nil {
		return err
	}

	dirKey := uint32(direction)
	actionValue := uint8(action)
	return objs.DefaultPolicy.Put(dirKey, actionValue)
}

// 기본 정책 조회
func GetDefaultPolicy(direction rule.Direction) (rule.Action, error) {
	if err := ensureObjsLoaded(); err != nil {
		return 0, err
	}

	dirKey := uint32(direction)
	var action uint8
	if err := objs.DefaultPolicy.Lookup(dirKey, &action); err != nil {
		return 0, fmt.Errorf("기본 정책 조회 실패: %w", err)
	}

	return rule.Action(action), nil
}

// 모든 규칙 읽기 (eBPF Map에서 직접 조회)
func GetAllRules() ([]rule.Rule, error) {
	if err := ensureObjsLoaded(); err != nil {
		return nil, err
	}

	var result []rule.Rule

	// eBPF Map의 모든 인덱스 순회
	for i := uint32(0); i < MaxRules; i++ {
		var cRule ebpf_fwFirewallRule

		// Map에서 규칙 읽기
		if err := objs.RulesArray.Lookup(i, &cRule); err != nil {
			continue // 읽기 실패하면 다음으로
		}

		// Valid가 0이면 비활성 규칙이므로 건너뛰기
		if cRule.Valid == 0 {
			continue
		}

		// C 구조체를 Go 구조체로 변환
		result = append(result, rule.Rule{
			SrcIP:     cRule.SrcIp,
			DstIP:     cRule.DstIp,
			Port:      cRule.Port,
			Protocol:  rule.Protocol(cRule.Protocol),
			Direction: rule.Direction(cRule.Direction),
			Action:    rule.Action(cRule.Action),
			Valid:     cRule.Valid,
		})
	}

	return result, nil
}
