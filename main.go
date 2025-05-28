package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// 보안 설정 상수들
const (
	ENCRYPTION_KEY    = 0x5A5A5A5A
	MAX_SAFE_SCORE    = 100000
	HEARTBEAT_TIMEOUT = 60 // 초
)

// 단일 클라이언트 정보
type TetrisClient struct {
	conn               net.Conn
	id                 string
	lastScore          int
	encryptedScore     int
	lastHeartbeat      time.Time
	lastScoreUpdate    time.Time
	isAuthenticated    bool
	securityViolations int
	highScoreStreak    int
}

// 1:1 서버 구조체
type Tetris1to1Server struct {
	port     string
	client   *TetrisClient // 단일 클라이언트
	listener net.Listener
	running  bool
	logFile  *os.File
}

// 보안 함수들
func encryptScore(score int) int {
	return score ^ ENCRYPTION_KEY
}

// 위험한 프로세스 검사
func checkDangerousProcesses() []string {
	dangerousProcesses := []string{
		"ollydbg.exe", "x64dbg.exe", "x32dbg.exe", "windbg.exe",
		"ida.exe", "ida64.exe", "cheatengine.exe", "artmoney.exe",
		"processhacker.exe", "procexp.exe", "procmon.exe",
	}

	var detected []string

	cmd := exec.Command("tasklist", "/FO", "CSV", "/NH")
	output, err := cmd.Output()
	if err != nil {
		return detected
	}

	outputStr := strings.ToLower(string(output))
	for _, process := range dangerousProcesses {
		if strings.Contains(outputStr, strings.ToLower(process)) {
			detected = append(detected, process)
		}
	}

	return detected
}

// 서버 초기화
func NewTetris1to1Server(port string) *Tetris1to1Server {
	logFile, err := os.OpenFile("tetris_1to1_server.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalln("Failed to open log file:", err)
	}

	server := &Tetris1to1Server{
		port:    port,
		client:  nil, // 초기에는 클라이언트 없음
		running: true,
		logFile: logFile,
	}

	server.logMessage("Tetris 1:1 Echo Server initialized")
	return server
}

// 로깅
func (s *Tetris1to1Server) logMessage(message string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("[%s] %s\n", timestamp, message)

	fmt.Print(logEntry)
	if s.logFile != nil {
		s.logFile.WriteString(logEntry)
		s.logFile.Sync()
	}
}

// 서버 시작
func (s *Tetris1to1Server) Start() error {
	var err error
	s.listener, err = net.Listen("tcp", ":"+s.port)
	if err != nil {
		return fmt.Errorf("failed to start server: %v", err)
	}

	s.logMessage(fmt.Sprintf("1:1 Server started on port %s", s.port))

	// 보안 모니터링 시작
	go s.securityMonitor()

	// 클라이언트 연결 대기 (1:1 모드)
	for s.running {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.running {
				s.logMessage(fmt.Sprintf("Error accepting connection: %v", err))
			}
			continue
		}

		// 기존 클라이언트가 있으면 연결 거부
		if s.client != nil {
			s.logMessage(fmt.Sprintf("Connection rejected: %s (Server busy)", conn.RemoteAddr().String()))
			conn.Write([]byte("ERROR:SERVER_BUSY\nTERMINATE:SERVER_BUSY\n"))
			conn.Close()
			continue
		}

		// 새 클라이언트 등록
		clientID := fmt.Sprintf("%s_%d", conn.RemoteAddr().String(), time.Now().Unix())
		s.client = &TetrisClient{
			conn:               conn,
			id:                 clientID,
			lastHeartbeat:      time.Now(),
			lastScoreUpdate:    time.Time{},
			isAuthenticated:    false,
			securityViolations: 0,
			highScoreStreak:    0,
		}

		s.logMessage(fmt.Sprintf("Client connected (1:1): %s", clientID))

		// 클라이언트 처리 (메인 스레드에서)
		s.handleClient()
	}

	return nil
}

// 보안 모니터링
func (s *Tetris1to1Server) securityMonitor() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for s.running {
		select {
		case <-ticker.C:
			// 위험한 프로세스 검사
			dangerousProcs := checkDangerousProcesses()
			if len(dangerousProcs) > 0 {
				s.logMessage(fmt.Sprintf("SERVER SECURITY ALERT: Dangerous processes detected: %v", dangerousProcs))
				s.terminateClient("SERVER_SECURITY_BREACH")
			}

			// 서버 메모리 사용량 검사
			var m runtime.MemStats
			runtime.ReadMemStats(&m)

			if m.Alloc > 100*1024*1024 {
				s.logMessage("SERVER WARNING: High memory usage detected")
			}

			// 클라이언트 하트비트 확인
			if s.client != nil && time.Since(s.client.lastHeartbeat) > HEARTBEAT_TIMEOUT*time.Second {
				s.logMessage("Client timeout detected")
				s.disconnectClient()
			}
		}
	}
}

// 클라이언트 처리 (단일 클라이언트)
func (s *Tetris1to1Server) handleClient() {
	defer s.disconnectClient()

	scanner := bufio.NewScanner(s.client.conn)

	for scanner.Scan() && s.running && s.client != nil {
		message := strings.TrimSpace(scanner.Text())
		if message == "" {
			continue
		}

		response := s.processMessage(message)

		// 응답 전송
		if s.client != nil && s.client.conn != nil {
			s.client.conn.Write([]byte(response + "\n"))
		}

		// 보안 위반 누적 시 연결 해제
		if s.client != nil && s.client.securityViolations >= 3 {
			s.logMessage(fmt.Sprintf("Client %s blocked due to security violations", s.client.id))
			s.terminateClient("SECURITY_VIOLATIONS_EXCEEDED")
			break
		}
	}
}

// 메시지 처리
func (s *Tetris1to1Server) processMessage(message string) string {
	if s.client == nil {
		return "ERROR:NO_CLIENT"
	}

	parts := strings.SplitN(message, ":", 2)
	if len(parts) < 2 {
		return "ERROR:INVALID_FORMAT"
	}

	command := parts[0]
	data := parts[1]

	logMsg := fmt.Sprintf("Received from %s: %s", s.client.id, message)

	switch command {
	case "SCORE":
		return s.handleScoreUpdate(data, &logMsg)

	case "SECURITY":
		return s.handleSecurityEvent(data, &logMsg)

	case "HEARTBEAT":
		s.client.lastHeartbeat = time.Now()
		return "STATUS_OK"

	case "AUTH":
		return s.handleAuthentication(data, &logMsg)

	default:
		logMsg += " [Unknown command]"
		s.logMessage(logMsg)
		return "ERROR:UNKNOWN_COMMAND"
	}
}

// 점수 업데이트 처리 (상세 검증)
func (s *Tetris1to1Server) handleScoreUpdate(data string, logMsg *string) string {
	// 새로운 프로토콜 파싱: SCORE:<점수>:<이벤트>:<증가량>:<추가정보>
	parts := strings.Split(data, ":")
	if len(parts) < 4 {
		// 구 버전 호환성: 단순 점수만 전송된 경우
		return s.handleSimpleScoreUpdate(data, logMsg)
	}

	score, err := strconv.Atoi(parts[0])
	if err != nil {
		*logMsg += " [Invalid score format]"
		s.client.securityViolations++
		s.logMessage(*logMsg)
		return "ERROR:INVALID_SCORE"
	}

	eventType := parts[1]
	scoreIncrease, err := strconv.Atoi(parts[2])
	if err != nil {
		*logMsg += " [Invalid score increase format]"
		s.client.securityViolations++
		s.logMessage(*logMsg)
		return "ERROR:INVALID_SCORE_INCREASE"
	}

	additionalInfo := 0
	if len(parts) > 3 {
		additionalInfo, _ = strconv.Atoi(parts[3])
	}

	// 기본 범위 검사
	if score < 0 {
		*logMsg += " [SECURITY ALERT: Negative score]"
		s.client.securityViolations += 2
		s.logMessage(*logMsg)
		return "TERMINATE:INVALID_SCORE"
	}

	if score > MAX_SAFE_SCORE {
		*logMsg += fmt.Sprintf(" [SECURITY ALERT: Score too high %d]", score)
		s.client.securityViolations += 2
		s.logMessage(*logMsg)
		return "TERMINATE:SUSPICIOUS_SCORE"
	}

	// 점수 일치성 검사
	expectedScore := s.client.lastScore + scoreIncrease
	if score != expectedScore {
		*logMsg += fmt.Sprintf(" [SECURITY ALERT: Score mismatch. Expected: %d, Got: %d]", expectedScore, score)
		s.client.securityViolations += 2
		s.logMessage(*logMsg)
		return "TERMINATE:SCORE_MISMATCH"
	}

	// 이벤트 타입별 상세 검증
	if !s.validateScoreEvent(eventType, scoreIncrease, additionalInfo, logMsg) {
		return "TERMINATE:INVALID_SCORE_EVENT"
	}

	// 시간 기반 검사
	now := time.Now()
	if !s.client.lastScoreUpdate.IsZero() {
		timeDiff := now.Sub(s.client.lastScoreUpdate).Seconds()

		// 이벤트 타입에 따른 최소 시간 간격 검사
		minInterval := s.getMinIntervalForEvent(eventType)
		if timeDiff < minInterval {
			*logMsg += fmt.Sprintf(" [SECURITY ALERT: Too frequent %s events %.2fs]", eventType, timeDiff)
			s.client.securityViolations++
			s.logMessage(*logMsg)
			return "TERMINATE:TOO_FREQUENT"
		}
	}

	// 패턴 분석
	if scoreIncrease >= 500 {
		s.client.highScoreStreak++
		if s.client.highScoreStreak >= 3 {
			*logMsg += " [SECURITY ALERT: Suspicious high score pattern]"
			s.client.securityViolations++
			s.logMessage(*logMsg)
			return "TERMINATE:SUSPICIOUS_PATTERN"
		}
	} else {
		s.client.highScoreStreak = 0
	}

	// 점수 업데이트 성공
	previousScore := s.client.lastScore
	s.client.lastScore = score
	s.client.encryptedScore = encryptScore(score)
	s.client.lastScoreUpdate = now

	*logMsg += fmt.Sprintf(" [%s: %d->%d, +%d, info:%d] ✓", eventType, previousScore, score, scoreIncrease, additionalInfo)
	s.logMessage(*logMsg)
	return "ACK"
}

// 이벤트별 상세 검증
func (s *Tetris1to1Server) validateScoreEvent(eventType string, scoreIncrease int, additionalInfo int, logMsg *string) bool {
	switch eventType {
	case "LINES_CLEAR":
		// 라인 클리어 검증
		linesCleared := additionalInfo
		expectedScore := 0

		switch linesCleared {
		case 1:
			expectedScore = 100
		case 2:
			expectedScore = 300
		case 3:
			expectedScore = 500
		case 4:
			expectedScore = 800
		default:
			*logMsg += fmt.Sprintf(" [SECURITY ALERT: Invalid lines cleared %d]", linesCleared)
			s.client.securityViolations++
			s.logMessage(*logMsg)
			return false
		}

		if scoreIncrease != expectedScore {
			*logMsg += fmt.Sprintf(" [SECURITY ALERT: Lines score mismatch. %d lines should give %d points, got %d]",
				linesCleared, expectedScore, scoreIncrease)
			s.client.securityViolations++
			s.logMessage(*logMsg)
			return false
		}
		return true

	case "SOFT_DROP":
		// 소프트 드롭: 1칸당 1점
		if scoreIncrease != additionalInfo || scoreIncrease > 20 {
			*logMsg += fmt.Sprintf(" [SECURITY ALERT: Invalid soft drop score %d]", scoreIncrease)
			s.client.securityViolations++
			s.logMessage(*logMsg)
			return false
		}
		return true

	case "HARD_DROP":
		// 하드 드롭: 1칸당 2점
		expectedScore := additionalInfo * 2
		if scoreIncrease != expectedScore || scoreIncrease > 40 {
			*logMsg += fmt.Sprintf(" [SECURITY ALERT: Invalid hard drop score %d (expected %d)]", scoreIncrease, expectedScore)
			s.client.securityViolations++
			s.logMessage(*logMsg)
			return false
		}
		return true

	case "GAME_START":
		// 게임 시작: 점수는 0이어야 함
		if scoreIncrease != 0 || s.client.lastScore != 0 {
			*logMsg += " [SECURITY ALERT: Invalid game start score]"
			s.client.securityViolations++
			s.logMessage(*logMsg)
			return false
		}
		return true

	case "UNKNOWN":
		// 알 수 없는 이벤트: 허용하지만 경고
		*logMsg += " [WARNING: Unknown score event]"
		return true

	default:
		*logMsg += fmt.Sprintf(" [SECURITY ALERT: Unrecognized event type %s]", eventType)
		s.client.securityViolations++
		s.logMessage(*logMsg)
		return false
	}
}

// 이벤트별 최소 시간 간격
func (s *Tetris1to1Server) getMinIntervalForEvent(eventType string) float64 {
	switch eventType {
	case "LINES_CLEAR":
		return 1.0 // 라인 클리어는 최소 1초 간격
	case "SOFT_DROP":
		return 0.1 // 소프트 드롭은 100ms 간격
	case "HARD_DROP":
		return 0.5 // 하드 드롭은 500ms 간격
	case "GAME_START":
		return 0.0 // 게임 시작은 제한 없음
	default:
		return 0.5 // 기본 500ms
	}
}

// 구 버전 호환성을 위한 단순 점수 처리
func (s *Tetris1to1Server) handleSimpleScoreUpdate(data string, logMsg *string) string {
	*logMsg += " [Legacy format - limited validation]"

	score, err := strconv.Atoi(data)
	if err != nil {
		*logMsg += " [Invalid score format]"
		s.client.securityViolations++
		s.logMessage(*logMsg)
		return "ERROR:INVALID_SCORE"
	}

	// 기본 검사만 수행
	if score < 0 || score > MAX_SAFE_SCORE {
		*logMsg += " [SECURITY ALERT: Invalid score range]"
		s.client.securityViolations += 2
		s.logMessage(*logMsg)
		return "TERMINATE:INVALID_SCORE"
	}

	// 단순 업데이트
	previousScore := s.client.lastScore
	s.client.lastScore = score
	s.client.encryptedScore = encryptScore(score)
	s.client.lastScoreUpdate = time.Now()

	*logMsg += fmt.Sprintf(" [Score: %d->%d] ✓ (Legacy)", previousScore, score)
	s.logMessage(*logMsg)
	return "ACK"
}

// 보안 이벤트 처리
func (s *Tetris1to1Server) handleSecurityEvent(data string, logMsg *string) string {
	*logMsg += fmt.Sprintf(" [Security Event: %s]", data)

	switch data {
	case "DEBUGGER_DETECTED", "MEMORY_TAMPERED", "CODE_TAMPERED":
		*logMsg += " [CRITICAL SECURITY VIOLATION]"
		s.client.securityViolations += 2
		s.logMessage(*logMsg)
		return "TERMINATE:" + data

	case "DEBUGGER_PROCESS_DETECTED":
		*logMsg += " [HIGH SECURITY VIOLATION]"
		s.client.securityViolations++
		s.logMessage(*logMsg)
		return "TERMINATE:" + data

	default:
		*logMsg += " [Unknown security event]"
		s.logMessage(*logMsg)
		return "ACK"
	}
}

// 인증 처리
func (s *Tetris1to1Server) handleAuthentication(data string, logMsg *string) string {
	expectedToken := "TETRIS_CLIENT_2025"

	if data == expectedToken {
		s.client.isAuthenticated = true
		*logMsg += " [Authentication successful]"
		s.logMessage(*logMsg)
		return "AUTH_SUCCESS"
	} else {
		*logMsg += " [Authentication failed]"
		s.client.securityViolations++
		s.logMessage(*logMsg)
		return "AUTH_FAILED"
	}
}

// 클라이언트 종료 요청
func (s *Tetris1to1Server) terminateClient(reason string) {
	if s.client != nil && s.client.conn != nil {
		message := "TERMINATE:" + reason + "\n"
		s.client.conn.Write([]byte(message))
		s.logMessage(fmt.Sprintf("Terminate sent to client: %s", reason))
	}
}

// 클라이언트 연결 해제
func (s *Tetris1to1Server) disconnectClient() {
	if s.client != nil {
		if s.client.conn != nil {
			s.client.conn.Close()
		}

		clientID := s.client.id
		s.client = nil // 클라이언트 제거

		s.logMessage(fmt.Sprintf("Client disconnected: %s", clientID))
	}
}

// 서버 상태 조회
func (s *Tetris1to1Server) getServerStatus() string {
	if s.client == nil {
		return "Server Status: Waiting for client connection..."
	}

	return fmt.Sprintf(`Server Status (1:1 Mode):
- Client: %s
- Score: %d
- Violations: %d
- High Score Streak: %d
- Last Heartbeat: %s
- Last Score Update: %s
- Authenticated: %t
- Server Running: %t`,
		s.client.id,
		s.client.lastScore,
		s.client.securityViolations,
		s.client.highScoreStreak,
		s.client.lastHeartbeat.Format("15:04:05"),
		s.client.lastScoreUpdate.Format("15:04:05"),
		s.client.isAuthenticated,
		s.running)
}

// 서버 종료
func (s *Tetris1to1Server) Stop() {
	s.running = false

	if s.client != nil {
		s.terminateClient("SERVER_SHUTDOWN")
		s.disconnectClient()
	}

	if s.listener != nil {
		s.listener.Close()
	}

	if s.logFile != nil {
		s.logFile.Close()
	}

	s.logMessage("1:1 Server stopped")
}

// 관리자 콘솔
func (s *Tetris1to1Server) handleConsoleCommands() {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Println("=== Tetris 1:1 Go Echo Server Console ===")
	fmt.Println("Commands: terminate <reason>, status, disconnect, quit")

	for s.running {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}

		command := strings.TrimSpace(scanner.Text())
		parts := strings.Fields(command)

		if len(parts) == 0 {
			continue
		}

		switch parts[0] {
		case "terminate":
			if s.client == nil {
				fmt.Println("No client connected")
				continue
			}
			reason := "ADMIN_COMMAND"
			if len(parts) > 1 {
				reason = strings.Join(parts[1:], "_")
			}
			s.terminateClient(reason)
			fmt.Printf("Termination sent to client: %s\n", reason)

		case "status":
			fmt.Println(s.getServerStatus())

		case "disconnect":
			if s.client == nil {
				fmt.Println("No client connected")
			} else {
				fmt.Printf("Disconnecting client: %s\n", s.client.id)
				s.disconnectClient()
			}

		case "quit":
			fmt.Println("Shutting down 1:1 server...")
			s.Stop()
			return

		default:
			fmt.Println("Available commands: terminate, status, disconnect, quit")
		}
	}
}

func main() {
	server := NewTetris1to1Server("8080")

	// 서버 시작
	go func() {
		if err := server.Start(); err != nil {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// 콘솔 명령어 처리
	server.handleConsoleCommands()
}
