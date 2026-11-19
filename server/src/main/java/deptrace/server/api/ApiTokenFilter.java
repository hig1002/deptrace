package deptrace.server.api;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import deptrace.server.config.DeptraceProperties;

/**
 * 쓰기 요청(SBOM 업로드, 재검사, 예외 등록·철회)은 토큰을 요구한다. CI가 Authorization: Bearer 토큰으로 호출한다.
 * GET·HEAD 외의 모든 메서드가 대상이다. 메서드를 하나씩 나열하면 새 쓰기 API(DELETE 등)가 빠질 수 있다.
 * 토큰을 설정하지 않으면 검사하지 않는다(로컬 개발용).
 */
@Component
public class ApiTokenFilter extends OncePerRequestFilter {

    private final byte[] token;

    public ApiTokenFilter(DeptraceProperties props) {
        this.token = props.apiToken() == null || props.apiToken().isBlank() ? null : props.apiToken().getBytes(StandardCharsets.UTF_8);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        boolean readOnly = request.getMethod().equals("GET") || request.getMethod().equals("HEAD");
        return token == null || readOnly || !request.getRequestURI().startsWith("/api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        byte[] given = header != null && header.startsWith("Bearer ")
                ? header.substring(7).getBytes(StandardCharsets.UTF_8) : new byte[0];
        // 비교 시간으로 토큰을 추측할 수 없게 상수 시간 비교를 쓴다
        if (!MessageDigest.isEqual(token, given)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "invalid token");
            return;
        }
        chain.doFilter(request, response);
    }
}
