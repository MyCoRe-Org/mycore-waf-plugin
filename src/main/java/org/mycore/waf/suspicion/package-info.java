/**
 * JAXB model of the XML based WAF suspicion rules. The rules are evaluated after a client solved
 * the Proof of Work challenge, against the client information gathered by the challenge page
 * JavaScript and the headers of the solution request. Facts can be combined with the {@code and},
 * {@code or} and {@code not} elements. If any rule of the root {@code suspicion-list} element
 * matches, the client is considered suspicious and has to solve an additional interaction
 * challenge.
 */
@XmlSchema(namespace = "http://www.mycore.org/waf/suspicion", elementFormDefault = XmlNsForm.QUALIFIED)
package org.mycore.waf.suspicion;

import jakarta.xml.bind.annotation.XmlNsForm;
import jakarta.xml.bind.annotation.XmlSchema;
