/*
 * This file is generated by jOOQ.
 */
package com.getreferral.client.jooq.tables.pojos;


import com.getreferral.client.jooq.tables.interfaces.ISpringSessionAttributes;

import java.util.Arrays;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class SpringSessionAttributes implements ISpringSessionAttributes {

    private static final long serialVersionUID = 1L;

    private String sessionPrimaryId;
    private String attributeName;
    private byte[] attributeBytes;

    public SpringSessionAttributes() {}

    public SpringSessionAttributes(ISpringSessionAttributes value) {
        this.sessionPrimaryId = value.getSessionPrimaryId();
        this.attributeName = value.getAttributeName();
        this.attributeBytes = value.getAttributeBytes();
    }

    public SpringSessionAttributes(
        String sessionPrimaryId,
        String attributeName,
        byte[] attributeBytes
    ) {
        this.sessionPrimaryId = sessionPrimaryId;
        this.attributeName = attributeName;
        this.attributeBytes = attributeBytes;
    }

    /**
     * Getter for
     * <code>jdbc_session.spring_session_attributes.SESSION_PRIMARY_ID</code>.
     */
    @Override
    public String getSessionPrimaryId() {
        return this.sessionPrimaryId;
    }

    /**
     * Setter for
     * <code>jdbc_session.spring_session_attributes.SESSION_PRIMARY_ID</code>.
     */
    @Override
    public void setSessionPrimaryId(String sessionPrimaryId) {
        this.sessionPrimaryId = sessionPrimaryId;
    }

    /**
     * Getter for
     * <code>jdbc_session.spring_session_attributes.ATTRIBUTE_NAME</code>.
     */
    @Override
    public String getAttributeName() {
        return this.attributeName;
    }

    /**
     * Setter for
     * <code>jdbc_session.spring_session_attributes.ATTRIBUTE_NAME</code>.
     */
    @Override
    public void setAttributeName(String attributeName) {
        this.attributeName = attributeName;
    }

    /**
     * Getter for
     * <code>jdbc_session.spring_session_attributes.ATTRIBUTE_BYTES</code>.
     */
    @Override
    public byte[] getAttributeBytes() {
        return this.attributeBytes;
    }

    /**
     * Setter for
     * <code>jdbc_session.spring_session_attributes.ATTRIBUTE_BYTES</code>.
     */
    @Override
    public void setAttributeBytes(byte[] attributeBytes) {
        this.attributeBytes = attributeBytes;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        final SpringSessionAttributes other = (SpringSessionAttributes) obj;
        if (this.sessionPrimaryId == null) {
            if (other.sessionPrimaryId != null)
                return false;
        }
        else if (!this.sessionPrimaryId.equals(other.sessionPrimaryId))
            return false;
        if (this.attributeName == null) {
            if (other.attributeName != null)
                return false;
        }
        else if (!this.attributeName.equals(other.attributeName))
            return false;
        if (this.attributeBytes == null) {
            if (other.attributeBytes != null)
                return false;
        }
        else if (!Arrays.equals(this.attributeBytes, other.attributeBytes))
            return false;
        return true;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((this.sessionPrimaryId == null) ? 0 : this.sessionPrimaryId.hashCode());
        result = prime * result + ((this.attributeName == null) ? 0 : this.attributeName.hashCode());
        result = prime * result + ((this.attributeBytes == null) ? 0 : Arrays.hashCode(this.attributeBytes));
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("SpringSessionAttributes (");

        sb.append(sessionPrimaryId);
        sb.append(", ").append(attributeName);
        sb.append(", ").append("[binary...]");

        sb.append(")");
        return sb.toString();
    }

    // -------------------------------------------------------------------------
    // FROM and INTO
    // -------------------------------------------------------------------------

    @Override
    public void from(ISpringSessionAttributes from) {
        setSessionPrimaryId(from.getSessionPrimaryId());
        setAttributeName(from.getAttributeName());
        setAttributeBytes(from.getAttributeBytes());
    }

    @Override
    public <E extends ISpringSessionAttributes> E into(E into) {
        into.from(this);
        return into;
    }
}
