package co.kubo.iam.web;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import co.kubo.iam.application.PaymentsService;
import co.kubo.iam.application.PlatformService;
import co.kubo.iam.application.dto.PlatformDtos.PlatformTotpRotation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

/**
 * Contrato HTTP del panel de plataforma (ADR-0025).
 *
 * La rotacion del segundo factor es la regresion que origino esta prueba: la
 * PWA llamaba a `POST /platform/totp/rotate` y el endpoint no existia (404).
 */
class PlatformControllerTest {

    private PlatformService platformService;
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        platformService = mock(PlatformService.class);

        mvc = MockMvcBuilders
                .standaloneSetup(new PlatformController(platformService, mock(PaymentsService.class)))
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    @DisplayName("POST /platform/totp/rotate entrega la URI nueva con sesion de plataforma")
    void rotaElSegundoFactor() throws Exception {
        when(platformService.rotateTotp(anyString(), anyString(), anyString()))
                .thenReturn(new PlatformTotpRotation("otpauth://totp/kubo", "SECRETO"));

        mvc.perform(post("/platform/totp/rotate")
                        .header("x-platform-admin-id", "00000000-0000-0000-0000-000000000001")
                        .header("x-platform-admin-email", "operador@kubo.local"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.otpauthUri").value("otpauth://totp/kubo"))
                .andExpect(jsonPath("$.secret").value("SECRETO"));
    }

    @Test
    @DisplayName("Sin sesion de plataforma la rotacion se rechaza")
    void sinSesionSeRechaza() throws Exception {
        mvc.perform(post("/platform/totp/rotate"))
                .andExpect(status().isForbidden());
    }
}
