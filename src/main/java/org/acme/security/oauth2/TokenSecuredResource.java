package org.acme.security.oauth2;

import java.security.Principal;

import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.SecurityContext;

@Path("/api")
@ApplicationScoped
public class TokenSecuredResource {

    @GET()
    @Path("/home")
    @PermitAll
    @Produces(MediaType.TEXT_PLAIN)
    public String hello(@Context SecurityContext ctx) {
        Principal caller =  ctx.getUserPrincipal();
        String name = caller == null ? "anonymous" : caller.getName();
        String helloReply = String.format("Hello %s, authScheme: %s", name, ctx.getAuthenticationScheme());
        return helloReply;
    }

    @GET()
    @Path("user-profile")
    @RolesAllowed("user")
    @Produces(MediaType.TEXT_PLAIN)
    public String helloRolesAllowed(@Context SecurityContext ctx) {
        Principal caller =  ctx.getUserPrincipal();
        String name = caller.getName();
        String helloReply = String.format("Hello %s has User Role, authScheme: %s", name, ctx.getAuthenticationScheme());
        return helloReply;
    }

    @GET()
    @Path("admin")
    @RolesAllowed("admin")
    @Produces(MediaType.TEXT_PLAIN)
    public String helloAdmin(@Context SecurityContext ctx) {
        Principal caller =  ctx.getUserPrincipal();
        String name = caller.getName();
        String helloReply = String.format("Hello  %s has Admin Role, authScheme: %s", name, ctx.getAuthenticationScheme());
        return helloReply;
    }
    @GET()
    @Path("dev")
    @RolesAllowed("dev")
    @Produces(MediaType.TEXT_PLAIN)
    public String helloDev(@Context SecurityContext ctx) {
        Principal caller =  ctx.getUserPrincipal();
        String name = caller.getName();
        String helloReply = String.format("Hello %s has Dev Role, authScheme: %s", name, ctx.getAuthenticationScheme());
        return helloReply;
    }

    @GET()
    @Path("manager")
    @RolesAllowed("manager")
    @Produces(MediaType.TEXT_PLAIN)
    public String helloManager(@Context SecurityContext ctx) {
        Principal caller =  ctx.getUserPrincipal();
        String name = caller.getName();
        String helloReply = String.format("Hello %s has Manager Role, authScheme: %s", name, ctx.getAuthenticationScheme());
        return helloReply;
    }

    @GET()
    @Path("manage-user")
    @RolesAllowed({"manager","admin"})
    @Produces(MediaType.TEXT_PLAIN)
    public String helloManagerAdmin(@Context SecurityContext ctx) {
        Principal caller =  ctx.getUserPrincipal();
        String name = caller.getName();
        String helloReply = String.format("Hello %s has Manager or Admin Role to manage a user, authScheme: %s", name, ctx.getAuthenticationScheme());
        return helloReply;
    }
}
