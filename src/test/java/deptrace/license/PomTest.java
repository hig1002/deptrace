package deptrace.license;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

import deptrace.license.Pom.DeclaredLicense;
import deptrace.model.Coordinate;

class PomTest {

    @Test
    void 라이선스와_부모_좌표를_읽는다() {
        Pom pom = Pom.parse("""
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <parent>
                    <groupId>ch.qos.logback</groupId>
                    <artifactId>logback-parent</artifactId>
                    <version>1.5.34</version>
                  </parent>
                  <licenses>
                    <license><name>EPL-2.0</name><url>https://www.eclipse.org/legal/epl-v20.html</url></license>
                    <license><name>LGPL-2.1-only</name></license>
                  </licenses>
                </project>
                """);

        assertThat(pom.licenses()).containsExactly(
                new DeclaredLicense("EPL-2.0", "https://www.eclipse.org/legal/epl-v20.html"),
                new DeclaredLicense("LGPL-2.1-only", null));
        assertThat(pom.parent()).contains(new Coordinate("ch.qos.logback", "logback-parent", "1.5.34"));
    }

    @Test
    void 의존성_안의_좌표를_부모로_착각하지_않는다() {
        Pom pom = Pom.parse("""
                <project>
                  <dependencies>
                    <dependency><groupId>g</groupId><artifactId>a</artifactId><version>1</version></dependency>
                  </dependencies>
                </project>
                """);

        assertThat(pom.licenses()).isEmpty();
        assertThat(pom.parent()).isEmpty();
    }

    @Test
    void 미해석_속성인_부모_버전은_따라가지_않는다() {
        Pom pom = Pom.parse("<project><parent><groupId>g</groupId><artifactId>p</artifactId><version>${revision}</version></parent></project>");

        assertThat(pom.parent()).isEmpty();
    }

    @Test
    void 이름의_줄바꿈과_공백을_정리한다() {
        Pom pom = Pom.parse("<project><licenses><license><name>\n  Apache License,\n  Version 2.0\n</name></license></licenses></project>");

        assertThat(pom.licenses()).extracting(DeclaredLicense::name).containsExactly("Apache License, Version 2.0");
    }

    @Test
    void DOCTYPE가_있는_POM은_거부한다_XXE_방지() {
        String xxe = """
                <?xml version="1.0"?>
                <!DOCTYPE project [<!ENTITY x SYSTEM "file:///etc/passwd">]>
                <project><licenses><license><name>&x;</name></license></licenses></project>
                """;

        assertThatThrownBy(() -> Pom.parse(xxe)).isInstanceOf(IllegalArgumentException.class);
    }
}
