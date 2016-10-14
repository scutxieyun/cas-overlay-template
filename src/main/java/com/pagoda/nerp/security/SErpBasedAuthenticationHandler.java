package com.pagoda.nerp.security;

import java.security.GeneralSecurityException;

import javax.security.auth.login.FailedLoginException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.commons.lang3.StringUtils;
import org.jasig.cas.adaptors.jdbc.AbstractJdbcUsernamePasswordAuthenticationHandler;
import org.jasig.cas.authentication.HandlerResult;
import org.jasig.cas.authentication.PreventedException;
import org.jasig.cas.authentication.UsernamePasswordCredential;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Component;



@Component("serpBaseAuthenticationHandler")
public class SErpBasedAuthenticationHandler extends AbstractJdbcUsernamePasswordAuthenticationHandler implements InitializingBean{
	
	protected final transient Logger logger = LoggerFactory.getLogger(this.getClass());
	static String sql_template = "select count(*) from SAM_USERS where USERCODE = '%1s' and sys_encrypt_des3('%2s',1) = PASSWORD";
	@Override
    protected final HandlerResult authenticateUsernamePasswordInternal(final UsernamePasswordCredential credential)
            throws GeneralSecurityException, PreventedException {
        if (StringUtils.isBlank(sql_template) || getJdbcTemplate() == null) {
            throw new GeneralSecurityException("Authentication handler is not configured correctly");
        }
        final String username = credential.getUsername();
        final String password = getPasswordEncoder().encode(credential.getPassword());
        final int count;
        final String sql = String.format(sql_template, username,password);
        try {
        	count = getJdbcTemplate().queryForObject(sql, Integer.class);
        } catch (final DataAccessException e) {
            throw new PreventedException("SQL exception while executing query for " + sql, e);
        }
        if (count == 0) {
            throw new FailedLoginException(username + " not found with SQL query.");
        }
        return createHandlerResult(credential, this.principalFactory.createPrincipal(username), null);
    }

	@Override
	public void afterPropertiesSet() throws Exception {
		// TODO Auto-generated method stub
		
	}
}