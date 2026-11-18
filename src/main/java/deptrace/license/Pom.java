package deptrace.license;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import deptrace.model.Coordinate;

/**
 * POM에서 라이선스 판정에 필요한 부분만 읽은 결과.
 *
 * <p>Maven은 {@code <licenses>}를 부모 POM에서 상속한다. 그래서 자기 POM에 라이선스가 없으면
 * 부모 좌표를 따라 올라가야 한다(예: spring-boot-starter-*는 자기 POM에 라이선스를 선언하지만,
 * 많은 Apache 프로젝트는 org.apache:apache 부모에서 상속받는다).
 *
 * @param licenses 선언 순서대로. 비어 있으면 이 POM에는 선언이 없다
 * @param parent   부모 POM 좌표. 없으면 empty
 */
public record Pom(List<DeclaredLicense> licenses, Optional<Coordinate> parent) {

    /** POM에 적힌 그대로의 라이선스. name·url 중 하나만 있는 경우도 많다. */
    public record DeclaredLicense(String name, String url) {
    }

    public static Pom parse(String xml) {
        Document doc = document(xml);
        Element project = doc.getDocumentElement();

        List<DeclaredLicense> licenses = new ArrayList<>();
        Element licensesEl = child(project, "licenses");
        if (licensesEl != null) {
            for (Element license : children(licensesEl, "license")) {
                String name = text(license, "name");
                String url = text(license, "url");
                if (name != null || url != null) {
                    licenses.add(new DeclaredLicense(name, url));
                }
            }
        }

        Optional<Coordinate> parent = Optional.empty();
        Element parentEl = child(project, "parent");
        if (parentEl != null) {
            String g = text(parentEl, "groupId");
            String a = text(parentEl, "artifactId");
            String v = text(parentEl, "version");
            // 배포된 POM의 부모 버전이 ${revision} 같은 미해석 속성이면 따라갈 수 없다
            if (g != null && a != null && v != null && !v.contains("${")) {
                parent = Optional.of(new Coordinate(g, a, v));
            }
        }
        return new Pom(List.copyOf(licenses), parent);
    }

    private static Document document(String xml) {
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            // 외부에서 받은 XML이므로 DTD·외부 엔티티를 막는다 (XXE 방지)
            f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            f.setFeature("http://xml.org/sax/features/external-general-entities", false);
            f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            f.setExpandEntityReferences(false);
            f.setNamespaceAware(false);
            DocumentBuilder b = f.newDocumentBuilder();
            b.setErrorHandler(null);
            return b.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalArgumentException("POM을 해석할 수 없습니다: " + e.getMessage(), e);
        }
    }

    private static Element child(Element parent, String name) {
        List<Element> list = children(parent, name);
        return list.isEmpty() ? null : list.get(0);
    }

    /** 직계 자식만 본다. getElementsByTagName은 하위 전체를 뒤져 dependency 안의 groupId까지 잡는다. */
    private static List<Element> children(Element parent, String name) {
        List<Element> out = new ArrayList<>();
        NodeList nodes = parent.getChildNodes();
        for (int i = 0; i < nodes.getLength(); i++) {
            Node n = nodes.item(i);
            if (n instanceof Element e && name.equals(e.getTagName())) {
                out.add(e);
            }
        }
        return out;
    }

    private static String text(Element parent, String name) {
        Element e = child(parent, name);
        if (e == null) {
            return null;
        }
        String t = e.getTextContent().strip().replaceAll("\\s+", " ");
        return t.isEmpty() ? null : t;
    }
}
