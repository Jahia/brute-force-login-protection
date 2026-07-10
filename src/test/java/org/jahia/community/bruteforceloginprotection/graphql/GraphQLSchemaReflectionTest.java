package org.jahia.community.bruteforceloginprotection.graphql;

import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import org.junit.Test;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * D1 — regression guard against the GraphQL schema silently drifting further away from
 * AGENTS.md's (stale) documentation: exact query/mutation surface counts and
 * {@code saveGlobalSettings}' parameter arity. This is a documentation-drift guard, not a
 * functional test -- the underlying features are already covered elsewhere (F12-a/F12-b etc.).
 */
public class GraphQLSchemaReflectionTest {

    private static List<Method> graphQLFields(Class<?> type) {
        return Arrays.stream(type.getDeclaredMethods())
                .filter(m -> m.isAnnotationPresent(GraphQLField.class))
                .collect(Collectors.toList());
    }

    @Test
    public void queryExposesExactlyNineFieldsIncludingBlocklistAndClusterStatus() {
        List<Method> fields = graphQLFields(BruteForceLoginProtectionQuery.class);
        List<String> names = fields.stream().map(Method::getName).collect(Collectors.toList());

        assertThat(names).hasSize(9);
        assertThat(names).containsExactlyInAnyOrder(
                "globalSettings", "jails", "bannedIps", "trackedWindows", "auditLog",
                "banActions", "configReady", "blocklistStatus", "clusterStatus");
    }

    @Test
    public void mutationExposesTenFieldsIncludingRefreshTorBlocklist() {
        List<Method> fields = graphQLFields(BruteForceLoginProtectionMutation.class);
        List<String> names = fields.stream().map(Method::getName).collect(Collectors.toList());

        assertThat(names).hasSize(10);
        assertThat(names).contains("refreshTorBlocklist", "saveGlobalSettings", "saveJail",
                "deleteJail", "unbanIp", "banIp", "flush", "clearAuditLog", "testEmail", "testWebhook");
    }

    @Test
    public void saveGlobalSettingsHasSeventeenParametersIncludingBlocklistFields() throws NoSuchMethodException {
        // NOTE: the gap-list narrative (D1, carried over from Stage 3) says 16; direct reflection
        // here shows the real, current count is 17 -- itself a small instance of the same
        // documentation-drift problem D1 flags. This assertion locks in the verified reality.
        Method m = Arrays.stream(BruteForceLoginProtectionMutation.class.getDeclaredMethods())
                .filter(x -> x.getName().equals("saveGlobalSettings"))
                .findFirst()
                .orElseThrow();

        assertThat(m.getParameterCount()).isEqualTo(17);
        List<String> paramNames = Arrays.stream(m.getParameters())
                .map(p -> p.getAnnotation(GraphQLName.class))
                .filter(java.util.Objects::nonNull)
                .map(GraphQLName::value)
                .collect(Collectors.toList());
        assertThat(paramNames).contains("blocklistIps", "torBlocklistEnabled", "torBlocklistUrl",
                "torBlocklistRefreshSeconds");
    }
}
