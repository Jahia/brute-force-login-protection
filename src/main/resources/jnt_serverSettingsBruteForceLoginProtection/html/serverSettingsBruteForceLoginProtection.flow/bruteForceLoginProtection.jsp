<%@ page language="java" contentType="text/html;charset=UTF-8" %>
<%@ taglib prefix="template" uri="http://www.jahia.org/tags/templateLib" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<%@ taglib prefix="jcr" uri="http://www.jahia.org/tags/jcr" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib prefix="functions" uri="http://www.jahia.org/tags/functions" %>
<%--@elvariable id="currentNode" type="org.jahia.services.content.JCRNodeWrapper"--%>
<%--@elvariable id="out" type="java.io.PrintWriter"--%>
<%--@elvariable id="script" type="org.jahia.services.render.scripting.Script"--%>
<%--@elvariable id="scriptInfo" type="java.lang.String"--%>
<%--@elvariable id="workspace" type="java.lang.String"--%>
<%--@elvariable id="renderContext" type="org.jahia.services.render.RenderContext"--%>
<%--@elvariable id="currentResource" type="org.jahia.services.render.Resource"--%>
<%--@elvariable id="url" type="org.jahia.services.render.URLGenerator"--%>
<%--@elvariable id="flowRequestContext" type="org.springframework.webflow.execution.RequestContext"--%>
<template:addResources type="javascript"
                       resources="jquery.min.js,jquery-ui.min.js,admin-bootstrap.js,bootstrapSwitch.js,regexValidation.js"/>
<template:addResources type="css" resources="jquery-ui.smoothness.css,jquery-ui.smoothness-jahia.css,bootstrapSwitch.css"/>

<script type="text/javascript">
    $(document).ready(function () {
        $('[data-toggle="tooltip"]').tooltip();
    });
</script>


<h2>
    <fmt:message key="bruteForceLoginProtection.settings"/>
</h2>
<p>
    <c:forEach items="${flowRequestContext.messageContext.allMessages}" var="message">
        <c:if test="${message.severity eq 'ERROR'}">
        <div class="alert alert-error">
            <button type="button" class="close" data-dismiss="alert">&times;</button>
            ${message.text}
        </div>
    </c:if>
</c:forEach>
</p>
<c:if test="${settingsUpdated}">
    <div class="alert alert-success">
        <button type="button" class="close" data-dismiss="alert">&times;</button>
        <fmt:message key="label.changeSaved"/>
    </div>
</c:if>
<div class="box-1">
    <form class="form-horizontal" id="bruteForceLoginProtectionSettings" name="bruteForceLoginProtectionSettings" action='${flowExecutionUrl}' method="post">
        <input type="hidden" name="_eventId" value="submitBruteForceLoginProtectionSettings"/>
        <div class="control-group" id="group-serviceActivated" data-error="<fmt:message key="bruteForceLoginProtection.errors.activated"/>">
            <label class="control-label"><fmt:message key="bruteForceLoginProtection.serviceStatus"/>&nbsp;:</label>
            <div class="controls">
                <input type="checkbox" name="activated" id="serviceActivated"<c:if test="${bruteForceLoginProtection.properties['activated'].boolean}"> checked="checked"</c:if>/>
                </div>
            </div>

            <div class="control-group" id="group-nbFailedLoginMax" data-error="<fmt:message key="bruteForceLoginProtection.errors.nb_failed_login_max"/>">
            <label class="control-label"><fmt:message key="bruteForceLoginProtection.nbFailedLoginMax"/>&nbsp;:</label>
            <div class="controls">
                <c:set var="nb_failed_login_max" value="${bruteForceLoginProtection.properties['nb_failed_login_max']}"/>
                <input type="text" name="nb_failed_login_max" id="nbFailedLoginMax" value="${nb_failed_login_max}"/>
            </div>
        </div>

        <div class="control-group" id="group-to" data-error="<fmt:message key="bruteForceLoginProtection.errors.whitelistIps"/>">
            <label class="control-label"><fmt:message key="label.whitelist"/>&nbsp;:</label>
            <div class="controls">
                <c:set var="whitelist_ips" value="${bruteForceLoginProtection.properties['whitelist_ips']}"/>
                <textarea rows="10" name="whitelist_ips" form="bruteForceLoginProtectionSettings" class="span12" id="whitelist_ips">${fn:escapeXml(whitelist_ips)}</textarea>
                <a class="btn btn-info" target="_blank" data-toggle="tooltip" data-placement="right" title="<fmt:message key="bruteForceLoginProtection.whitelistIpsTooltip"/>">
                    <i class="icon-info-sign icon-white"></i>
                </a>
            </div>
        </div>
        <div class="control-group">
            <div class="controls">
                <button class="btn btn-primary" type="submit">
                    <i class="icon-${'share'} icon-white"></i>
                    &nbsp;<fmt:message key="label.${'update'}"/>
                </button>
            </div>
        </div>
    </form>
    <form class="form-horizontal" id="bruteForceLoginProtectionSettings" name="bruteForceLoginProtectionSettings" action='${flowExecutionUrl}' method="post">
        <input type="hidden" name="_eventId" value="flushBruteForceLoginProtectionSettings"/>
        <div class="control-group">
            <div class="controls">
                <button class="btn btn-primary" type="submit">
                    <i class="icon-${'share'} icon-white"></i>
                    &nbsp;<fmt:message key="label.${'flush'}"/>
                </button>
            </div>
        </div>
    </form>
</div>
