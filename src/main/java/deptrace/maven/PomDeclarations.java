package deptrace.maven;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * pom.xml의 직접 의존성 선언({@code project/dependencies/dependency})에 버전이 적혀 있는지 읽는다.
 *
 * <p>트리 출력만으로는 직접 의존성의 버전이 pom.xml에 적힌 것인지, dependencyManagement(부모 POM·BOM import)에서
 * 온 것인지 구분할 수 없다. Maven에서 직접 선언한 버전은 관리 버전보다 우선하므로, 이 구분이 수정 지점을 바꾼다.
 * dependencyManagement 안의 선언과 profile 안의 선언은 보지 않는다.
 */
public final class PomDeclarations {

    private PomDeclarations() {
    }

    public static List<MavenTreeParser.Declared> parse(String pomXml) {
        try {
            DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
            f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            f.setExpandEntityReferences(false);
            var b = f.newDocumentBuilder();
            b.setErrorHandler(null);
            Element project = b.parse(new ByteArrayInputStream(pomXml.getBytes(StandardCharsets.UTF_8))).getDocumentElement();
            Element deps = child(project, "dependencies");
            List<MavenTreeParser.Declared> out = new ArrayList<>();
            if (deps == null) {
                return out;
            }
            for (Element d : children(deps, "dependency")) {
                String g = text(d, "groupId");
                String a = text(d, "artifactId");
                if (g != null && a != null) {
                    out.add(new MavenTreeParser.Declared(g + ":" + a, text(d, "version") != null));
                }
            }
            return out;
        } catch (Exception e) {
            throw new IllegalArgumentException("pom.xml을 해석할 수 없습니다: " + e.getMessage(), e);
        }
    }

    private static Element child(Element parent, String name) {
        List<Element> l = children(parent, name);
        return l.isEmpty() ? null : l.get(0);
    }

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
        String t = e.getTextContent().strip();
        return t.isEmpty() ? null : t;
    }
}
