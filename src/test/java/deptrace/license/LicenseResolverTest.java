package deptrace.license;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import deptrace.license.LicenseResolver.ComponentLicense;
import deptrace.license.LicenseResolver.Status;
import deptrace.model.Coordinate;

class LicenseResolverTest {

    private static final Coordinate CORE = new Coordinate("ch.qos.logback", "logback-core", "1.5.34");
    private static final Coordinate PARENT = new Coordinate("ch.qos.logback", "logback-parent", "1.5.34");

    private static String pom(String parent, String licenses) {
        return "<project>" + (parent == null ? "" : parent) + (licenses == null ? "" : "<licenses>" + licenses + "</licenses>") + "</project>";
    }

    private static String parent(Coordinate c) {
        return "<parent><groupId>" + c.group() + "</groupId><artifactId>" + c.artifact() + "</artifactId><version>" + c.version()
                + "</version></parent>";
    }

    private static PomSource source(Map<Coordinate, String> poms) {
        return c -> Optional.ofNullable(poms.get(c));
    }

    @Test
    void 자기_POM에_없으면_부모에서_상속받는다() {
        LicenseResolver resolver = new LicenseResolver(source(Map.of(
                CORE, pom(parent(PARENT), null),
                PARENT, pom(null, "<license><name>EPL-2.0</name></license><license><name>LGPL-2.1-only</name></license>"))));

        ComponentLicense l = resolver.resolve(CORE);

        assertThat(l.status()).isEqualTo(Status.INHERITED);
        assertThat(l.declaredIn()).isEqualTo(PARENT.toString());
        assertThat(l.expression()).isEqualTo("EPL-2.0 OR LGPL-2.1-only");
    }

    @Test
    void 다중_라이선스는_가장_제약이_적은_분류로_판정한다() {
        LicenseResolver resolver = new LicenseResolver(source(Map.of(CORE, pom(null,
                "<license><name>GPL-3.0</name></license><license><name>MIT</name></license>"))));

        ComponentLicense l = resolver.resolve(CORE);

        assertThat(l.multiple()).isTrue();
        assertThat(l.category()).isEqualTo(LicenseCategory.PERMISSIVE);
    }

    @Test
    void 부모_체인_끝까지_선언이_없으면_미확인이다() {
        LicenseResolver resolver = new LicenseResolver(source(Map.of(CORE, pom(parent(PARENT), null), PARENT, pom(null, null))));

        ComponentLicense l = resolver.resolve(CORE);

        assertThat(l.status()).isEqualTo(Status.NOT_DECLARED);
        assertThat(l.category()).isEqualTo(LicenseCategory.UNKNOWN);
        assertThat(l.expression()).isEqualTo("NOASSERTION");
    }

    @Test
    void 부모가_자기_자신을_가리켜도_멈춘다() {
        LicenseResolver resolver = new LicenseResolver(source(Map.of(CORE, pom(parent(CORE), null))));

        assertThat(resolver.resolve(CORE).status()).isEqualTo(Status.NOT_DECLARED);
    }

    @Test
    void POM을_받지_못하면_그렇게_표시한다() {
        assertThat(new LicenseResolver(source(Map.of())).resolve(CORE).status()).isEqualTo(Status.POM_UNAVAILABLE);
    }

    @Test
    void 식별하지_못한_선언은_원문을_남긴다() {
        LicenseResolver resolver = new LicenseResolver(source(Map.of(CORE, pom(null, "<license><name>Custom License</name></license>"))));

        ComponentLicense l = resolver.resolve(CORE);

        assertThat(l.category()).isEqualTo(LicenseCategory.UNKNOWN);
        assertThat(l.unmatched()).containsExactly("Custom License");
    }
}
