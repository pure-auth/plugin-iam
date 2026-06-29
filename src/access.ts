import { forbidden, notFound, type SessionActor } from "@pure-auth/core";
import { requireOrganizationMembership } from "@pure-auth/plugin-organization";
import type { Member } from "@pure-auth/plugin-organization";
import type { IamPluginStorage } from "./storage";
import type { Action, ApiKeyActor, Resource } from "./types";

export type IamActor = SessionActor | ApiKeyActor;

export type ResourceAccess = {
  resource: Resource;
  membership?: Member;
};

export async function requireResourceAction(
  storage: IamPluginStorage,
  resourceId: string,
  action: Action,
  actor: IamActor,
): Promise<ResourceAccess> {
  const resource = await storage.resources.findById(resourceId);
  if (!resource) {
    throw notFound("Resource not found");
  }

  await assertResourceAction(storage, resource, action, actor);

  if (actor.type === "apiKey") {
    return { resource };
  }

  return {
    resource,
    membership:
      (await storage.members.findMembership(
        resource.organizationId,
        actor.user.id,
      )) ?? undefined,
  };
}

export async function canAccessResource(
  storage: IamPluginStorage,
  resource: Resource,
  action: Action,
  actor: IamActor,
): Promise<boolean> {
  try {
    await assertResourceAction(storage, resource, action, actor);
    return true;
  } catch (error) {
    if (
      error instanceof Error &&
      "status" in error &&
      (error.status === 403 || error.status === 404)
    ) {
      return false;
    }

    throw error;
  }
}

export async function requireResourceAdministration(
  storage: IamPluginStorage,
  organizationId: string,
  actor: IamActor,
): Promise<Member> {
  if (actor.type === "apiKey") {
    throw forbidden("API keys cannot administer resources");
  }

  return requireOrganizationMembership(storage, organizationId, actor.user.id, [
    "owner",
    "admin",
  ]);
}

export async function requireResourceListScope(
  storage: IamPluginStorage,
  organizationId: string,
  actor: IamActor,
): Promise<Member | undefined> {
  if (actor.type === "apiKey") {
    if (actor.organizationId !== organizationId) {
      throw notFound("Organization not found");
    }

    return undefined;
  }

  return requireOrganizationMembership(storage, organizationId, actor.user.id);
}

async function assertResourceAction(
  storage: IamPluginStorage,
  resource: Resource,
  action: Action,
  actor: IamActor,
): Promise<void> {
  if (actor.type === "apiKey") {
    await assertApiKeyResourceAction(storage, resource, action, actor);
    return;
  }

  const membership = await storage.members.findMembership(
    resource.organizationId,
    actor.user.id,
  );

  if (!membership) {
    throw notFound("Resource not found");
  }

  if (membership.roleType === "owner" || membership.roleType === "admin") {
    return;
  }

  if (!membership.roleId) {
    throw forbidden("Insufficient resource permissions");
  }

  await assertRolePermission(storage, membership.roleId, resource, action);
}

async function assertApiKeyResourceAction(
  storage: IamPluginStorage,
  resource: Resource,
  action: Action,
  actor: ApiKeyActor,
): Promise<void> {
  if (resource.organizationId !== actor.organizationId) {
    throw notFound("Resource not found");
  }

  if (!actor.roleId) {
    throw forbidden("Insufficient resource permissions");
  }

  await assertRolePermission(storage, actor.roleId, resource, action);
}

async function assertRolePermission(
  storage: IamPluginStorage,
  roleId: string,
  resource: Resource,
  action: Action,
): Promise<void> {
  const allowed = await storage.permissions.hasRoleResourceAction({
    roleId,
    resourceId: resource.id,
    resourceType: resource.type,
    action,
  });

  if (!allowed) {
    throw forbidden("Insufficient resource permissions");
  }
}
