package org.jahia.community.bruteforceloginprotection.core;

import org.jahia.services.content.JCRNodeIteratorWrapper;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRPropertyWrapper;
import org.jahia.services.content.JCRSessionWrapper;

import javax.jcr.PathNotFoundException;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Minimal Mockito-backed in-memory fake JCR node tree covering exactly the
 * {@link JCRNodeWrapper}/{@link JCRSessionWrapper} surface exercised by
 * {@code AuditLogger}/{@code BruteForceTracker}'s JCR-backed code paths: hasNode, getNode, addNode,
 * getNodes, hasProperty, getProperty, setProperty(String/long), remove, isNodeType, addMixin,
 * getSession. Not a general-purpose JCR mock -- shared across the JCR-mocking tests introduced by
 * SUPPORT-646 (F10, F18-a, U11, U1, F27) so each doesn't hand-roll its own fixture.
 */
final class FakeJcrNode {

    private final String name;
    private String primaryType;
    private final Map<String, FakeJcrNode> children = new LinkedHashMap<>();
    private final Map<String, Object> properties = new LinkedHashMap<>();
    private final Set<String> mixins = new HashSet<>();
    private FakeJcrNode parent;
    private JCRNodeWrapper mockNode;
    private final SessionHolder sessionHolder;

    private FakeJcrNode(String name, String primaryType, SessionHolder sessionHolder) {
        this.name = name;
        this.primaryType = primaryType;
        this.sessionHolder = sessionHolder;
    }

    /** Holds the (lazily bound) session mock shared by every node in the tree. */
    static final class SessionHolder {
        JCRSessionWrapper session;
    }

    static FakeJcrNode newRoot(String name, String primaryType) {
        FakeJcrNode root = new FakeJcrNode(name, primaryType, new SessionHolder());
        try {
            root.mockNode = root.buildMock();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return root;
    }

    void bindSession(JCRSessionWrapper session) {
        sessionHolder.session = session;
    }

    JCRNodeWrapper asMock() {
        return mockNode;
    }

    void setProperty(String key, Object value) {
        properties.put(key, value);
    }

    Object getRawProperty(String key) {
        return properties.get(key);
    }

    boolean isRemoved() {
        return parent != null && !parent.children.containsKey(name);
    }

    int childCount() {
        return children.size();
    }

    private JCRNodeWrapper buildMock() throws Exception {
        JCRNodeWrapper m = mock(JCRNodeWrapper.class);
        when(m.getName()).thenReturn(name);
        when(m.hasNode(anyString())).thenAnswer(inv -> children.containsKey((String) inv.getArgument(0)));
        when(m.getNode(anyString())).thenAnswer(inv -> {
            FakeJcrNode c = children.get((String) inv.getArgument(0));
            if (c == null) {
                throw new PathNotFoundException((String) inv.getArgument(0));
            }
            return c.asMock();
        });
        when(m.addNode(anyString(), anyString())).thenAnswer(inv -> {
            String cname = inv.getArgument(0);
            String ntype = inv.getArgument(1);
            FakeJcrNode child = new FakeJcrNode(cname, ntype, sessionHolder);
            child.parent = this;
            child.mockNode = child.buildMock();
            children.put(cname, child);
            return child.asMock();
        });
        when(m.getNodes()).thenAnswer(inv -> fakeIterator(new ArrayList<>(children.values())));
        when(m.hasProperty(anyString())).thenAnswer(inv -> properties.containsKey((String) inv.getArgument(0)));
        when(m.getProperty(anyString())).thenAnswer(inv -> {
            String key = inv.getArgument(0);
            if (!properties.containsKey(key)) {
                throw new PathNotFoundException(key);
            }
            return fakeProperty(properties.get(key));
        });
        when(m.setProperty(anyString(), org.mockito.ArgumentMatchers.anyString())).thenAnswer(inv -> {
            properties.put(inv.getArgument(0), inv.getArgument(1));
            return fakeProperty(inv.getArgument(1));
        });
        when(m.setProperty(anyString(), anyLong())).thenAnswer(inv -> {
            properties.put(inv.getArgument(0), inv.getArgument(1));
            return fakeProperty(inv.getArgument(1));
        });
        when(m.isNodeType(anyString())).thenAnswer(inv ->
                primaryType != null && primaryType.equals(inv.getArgument(0)) || mixins.contains(inv.getArgument(0)));
        doAnswer(inv -> {
            mixins.add((String) inv.getArgument(0));
            return null;
        }).when(m).addMixin(anyString());
        doAnswer(inv -> {
            if (parent != null) {
                parent.children.remove(name);
            }
            return null;
        }).when(m).remove();
        when(m.getSession()).thenAnswer(inv -> sessionHolder.session);
        return m;
    }

    private static JCRNodeIteratorWrapper fakeIterator(List<FakeJcrNode> nodes) throws Exception {
        JCRNodeIteratorWrapper it = mock(JCRNodeIteratorWrapper.class);
        Iterator<FakeJcrNode> real = nodes.iterator();
        when(it.hasNext()).thenAnswer(inv -> real.hasNext());
        when(it.nextNode()).thenAnswer(inv -> real.next().asMock());
        return it;
    }

    private static JCRPropertyWrapper fakeProperty(Object value) {
        JCRPropertyWrapper p = mock(JCRPropertyWrapper.class);
        try {
            if (value instanceof Long || value instanceof Integer) {
                when(p.getLong()).thenReturn(((Number) value).longValue());
            }
            if (value instanceof String) {
                when(p.getString()).thenReturn((String) value);
            }
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return p;
    }
}
