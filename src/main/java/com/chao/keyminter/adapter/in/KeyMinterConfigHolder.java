package com.chao.keyminter.adapter.in;

import lombok.NonNull;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Component;

@Component
public class KeyMinterConfigHolder implements ApplicationContextAware {

    private static ApplicationContext ctx;

    @Override
    public void setApplicationContext(@NonNull ApplicationContext applicationContext) {
        ctx = applicationContext;
    }

    public static KeyMinterProperties get() {
        if (ctx == null) {
            return new KeyMinterProperties();
        }
        return ctx.getBean(KeyMinterProperties.class);
    }
}