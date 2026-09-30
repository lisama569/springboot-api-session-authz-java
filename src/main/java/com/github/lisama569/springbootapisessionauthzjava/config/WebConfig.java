package com.github.lisama569.springbootapisessionauthzjava.config;

import com.github.lisama569.springbootapisessionauthzjava.authz.AuthInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * 将鉴权拦截器挂载到受保护资源路径上。
 * 会话与策略管理接口（/api/sessions/**、/api/policies/**）是本地开发设施，不经过拦截器。
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final AuthInterceptor authInterceptor;

    public WebConfig(AuthInterceptor authInterceptor) {
        this.authInterceptor = authInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(authInterceptor)
                .addPathPatterns("/api/resources/**");
    }
}
