package com.carland.carland_auth.filter;

import com.carland.carland_auth.service.AuthFlowLogService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.IOException;
import java.util.Locale;

/**
 * Captures request/response bodies + HTTP status for login/logout diagnosis paths.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
@RequiredArgsConstructor
public class AuthSessionLogFilter extends OncePerRequestFilter {

    private static final int CACHE_LIMIT = 64 * 1024;

    private final AuthFlowLogService authFlowLogService;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        if (path == null) {
            return true;
        }
        String p = path.toLowerCase(Locale.ROOT);
        return !(p.contains("/api/v1/newusers")
                || p.endsWith("/api/v1/users/login")
                || p.endsWith("/api/v1/users/refresh"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        ContentCachingRequestWrapper req = request instanceof ContentCachingRequestWrapper r
                ? r
                : new ContentCachingRequestWrapper(request, CACHE_LIMIT);
        ContentCachingResponseWrapper res = response instanceof ContentCachingResponseWrapper r
                ? r
                : new ContentCachingResponseWrapper(response);

        authFlowLogService.ensureTraceId(req);
        try {
            filterChain.doFilter(req, res);
        } finally {
            try {
                String action = AuthFlowLogService.actionForPath(req.getMethod(), req.getRequestURI());
                authFlowLogService.recordHttp(req, res, action);
            } finally {
                res.copyBodyToResponse();
            }
        }
    }
}
