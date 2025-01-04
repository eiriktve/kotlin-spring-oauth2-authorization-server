package no.stackcanary.authorizationserver.config

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.security.web.SecurityFilterChain
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Duration
import java.util.*


@Configuration
@EnableWebSecurity
class SecurityConfig {

    /**
     * Configures the default functionality of the authorization Server, such as initializing the different endpoints.
     */
    @Bean
    fun authorizationServerSettings(): AuthorizationServerSettings =
        AuthorizationServerSettings.builder().build()

    /*
    For removal in 2.0. Use HttpSecurity.with(SecurityConfigurerAdapter, Customizer) and pass in OAuth2AuthorizationServerConfigurer.authorizationServer().
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    fun authServerSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        val authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer.authorizationServer();
        return http
            .securityMatcher(authorizationServerConfigurer.endpointsMatcher)
            .with(authorizationServerConfigurer, Customizer.withDefaults())
            .build()

    }

    /**
     * Registers a couple of default clients we can use for our projects. One is a base client with all
     * permissions/scopes, another one is for the resource server.
     */
    @Bean
    fun registeredClientRepository(jdbcTemplate: JdbcTemplate): RegisteredClientRepository {
        val baseClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("stackcanary-client" )
            .clientSecret(passwordEncoder().encode("hunter2"))
            .clientAuthenticationMethods { authMethods: MutableSet<ClientAuthenticationMethod> ->
                authMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                authMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            }
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .scope("client.create") // allow the client to register a new client
            .scope("client.read") // allow the client to retrieve a registered client
            // custom scopes for an employee domain / protected resource
            .scope("employee.read")
            .scope("employee.edit")
            .scope("employee.create")
            .scope("employee.delete")
            .clientSettings(
                ClientSettings.builder()
                    .requireAuthorizationConsent(true)
                    .requireProofKey(false)
                    .build()
            )
            .tokenSettings(
                TokenSettings.builder()
                    .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                    .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                    .accessTokenTimeToLive(Duration.ofSeconds((30 * 60).toLong()))
                    .refreshTokenTimeToLive(Duration.ofSeconds((60 * 60).toLong()))
                    .reuseRefreshTokens(true)
                    .build()
            )
            .build()

        // The resource server needs its own credentials to be able to call the introspection endpoint in order to
        // validate incoming tokens
        val resourceServerClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("resource-server-client" )
            .clientSecret(passwordEncoder().encode("resource-server-secret"))
            .clientAuthenticationMethods { authMethods: MutableSet<ClientAuthenticationMethod> ->
                authMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                authMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            }
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .build()

        val registeredClientRepository = JdbcRegisteredClientRepository(jdbcTemplate)

        // for convenience, as clients must be unique, and you'll most likely restart the service multiple times
        // during development (and we're not running an in-memory db)
        if (!exists(baseClient, registeredClientRepository)) {
            registeredClientRepository.save(baseClient)
        }

        if (!exists(resourceServerClient, registeredClientRepository)) {
            registeredClientRepository.save(resourceServerClient)
        }

        return registeredClientRepository
    }

    private fun exists(client: RegisteredClient, repository: JdbcRegisteredClientRepository): Boolean =
        repository.findByClientId(client.clientId) != null

    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()

    /**
     * Stores new authorizations and queries existing ones
     */
    @Bean
    fun authorizationService(
        jdbcTemplate: JdbcTemplate,
        registeredClientRepository: RegisteredClientRepository
    ): OAuth2AuthorizationService =
        JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository)


    /**
     * Stores new authorization consents and queries existing ones
     */
    @Bean
    fun authorizationConsentService(
        jdbcTemplate: JdbcTemplate,
        registeredClientRepository: RegisteredClientRepository
    ): OAuth2AuthorizationConsentService =
        JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository)


    @Bean
    fun jwkSource(): JWKSource<SecurityContext> {
        val keyPair = generateRsaKey()
        val publicKey = keyPair.public as RSAPublicKey
        val privateKey = keyPair.private as RSAPrivateKey
        val rsaKey: RSAKey = RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build()
        val jwkSet = JWKSet(rsaKey)
        return ImmutableJWKSet<SecurityContext>(jwkSet)
    }

    /**
     * JwtDecoder for decoding signed access tokens
     */
    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder =
        OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)


    companion object {
        /**
         * KeyPair with keys generated on startup used to create the JWKSource above
         */
        private fun generateRsaKey(): KeyPair =
            try {
                val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
                keyPairGenerator.initialize(2048)
                keyPairGenerator.generateKeyPair()
            } catch (ex: Exception) { throw IllegalStateException(ex) }

    }
}
