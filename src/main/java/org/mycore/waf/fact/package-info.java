/**
 * JAXB model of the XML based WAF allow rules. Every element is a fact that is evaluated against
 * an incoming {@link jakarta.servlet.http.HttpServletRequest}. Facts can be combined with the
 * {@code and}, {@code or} and {@code not} elements. If any rule of the root {@code allow-list}
 * element matches, the request bypasses the WAF challenge.
 */
@XmlSchema(namespace = "http://www.mycore.org/waf", elementFormDefault = XmlNsForm.QUALIFIED)
package org.mycore.waf.fact;

import jakarta.xml.bind.annotation.XmlNsForm;
import jakarta.xml.bind.annotation.XmlSchema;
