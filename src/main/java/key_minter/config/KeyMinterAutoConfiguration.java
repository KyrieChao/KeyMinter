package key_minter.config;

import key_minter.auth.core.Jwt;
import key_minter.model.dto.Algorithm;
import key_minter.auth.factory.JwtFactory;
import key_minter.util.KeyMinter;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import java.util.List;

@AutoConfiguration
@EnableConfigurationProperties(KeyMinterProperties.class)
@ConditionalOnClass({JwtFactory.class, Algorithm.class})
public class KeyMinterAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(KeyMinterOverrides.class)
    public KeyMinterOverrides keyMinterOverrides(KeyMinterProperties properties) {
        return new PropertiesKeyMinterOverrides(properties);
    }

    @Bean
    public Jwt keyMinterJwt(KeyMinterProperties properties, KeyMinterOverrides overrides,
                            ObjectProvider<List<KeyMinterConfigurer>> configurersProvider) {

        KeyMinterBuilder builder = new KeyMinterBuilder()
                .setAlgorithm(overrides.algorithm() != null ? overrides.algorithm() : properties.getAlgorithm())
                .setPreferredKeyId(overrides.preferredKeyId() != null ? overrides.preferredKeyId() : properties.getPreferredKeyId());

        List<KeyMinterConfigurer> configurers = configurersProvider.getIfAvailable();
        if (configurers != null) {
            for (KeyMinterConfigurer configurer : configurers) {
                configurer.configure(builder);
            }
        }

        Algorithm algorithm = builder.getAlgorithm() != null ? builder.getAlgorithm() : Algorithm.HMAC256;
        String preferredKeyId = builder.getPreferredKeyId();
        String directory = properties.getKeyDir();

        return JwtFactory.autoLoad(algorithm, directory, preferredKeyId,
                properties.isEnableRotation(), properties.isForceLoad());
    }

    @Bean
    @ConditionalOnMissingBean(KeyMinter.class)
    public KeyMinter keyMinterBean() {
        return new KeyMinter();
    }
}
