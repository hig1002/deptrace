## DepTrace 정책 게이트: 통과 (기준: 배포 클래스패스, HIGH 이상)


예외로 인정된 항목

- org.springframework:spring-webflux:6.2.19 GHSA-9qf2-26p9-2q2q — WebFlux 함수형 엔드포인트(RouterFunction·RequestPredicates)의 헤더 조건 우회 취약점. 경매톡은 WebFlux를 외부 API 호출용 WebClient로만 쓰며 서버 측 RouterFunction을 정의하지 않는다(검색 0건). (만료 2027-01-19)
- org.springframework:spring-webflux:6.2.19 GHSA-j9f9-w8pj-32f8 — Server-Sent Events 스트림 렌더링 취약점. SseEmitter·ServerSentEvent·text/event-stream 응답을 쓰지 않는다(검색 0건). (만료 2027-01-19)
- org.springframework:spring-webmvc:6.2.19 GHSA-j9f9-w8pj-32f8 — Server-Sent Events 스트림 렌더링 취약점. SseEmitter·ServerSentEvent·text/event-stream 응답을 쓰지 않는다(검색 0건). (만료 2027-01-19)
- org.springframework:spring-webmvc:6.2.19 GHSA-pc63-qcmh-9cmg — XsltView 경로 제한 취약점. XsltView와 XSLT 뷰를 쓰지 않는다(검색 0건). (만료 2027-01-19)
- com.querydsl:querydsl-jpa:5.0.0 GHSA-6q3q-6v5j-h6vg — orderBy에 사용자 입력이 전달될 때의 HQL 인젝션. 유일한 orderBy는 CounselDslRepositoryImpl의 counsel.createdAt.desc() 고정 정렬이며 외부 입력을 받지 않는다. 수정은 OpenFeign 포크 (io.github.openfeign.querydsl:querydsl-jpa 6.10.1)로의 좌표 이전이 필요해 후속 과제로 둔다. (만료 2027-01-19)
