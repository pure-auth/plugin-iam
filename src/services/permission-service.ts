import {
  badRequest,
  internal,
  notFound,
  type ListOptions,
  type ServiceContext,
} from "pure-auth";
import { requireOrganizationMembership } from "@pure-auth/plugin-organization";
import type { IamPluginStorage, PermissionOrderBy } from "@/storage";
import type {
  CreatePermissionInput,
  Permission,
  Role,
  UpdatePermissionInput,
} from "@/types";

const permissionOrderByValues = [
  "resourceType",
  "createdAt",
  "updatedAt",
] as const;

export type PermissionListFilter = {
  organizationId?: string;
};

export class PermissionService {
  constructor(private readonly storage: IamPluginStorage) {}

  async get(id: string, context: ServiceContext): Promise<Permission> {
    const { permission } = await this.requirePermissionAccess(id, context);
    return permission;
  }

  async create(
    input: CreatePermissionInput,
    context: ServiceContext,
  ): Promise<Permission> {
    const role = await this.requireManagedRole(input.roleId, context);
    const resource = await this.storage.resources.findById(input.resourceId);

    if (!resource || resource.organizationId !== role.organizationId) {
      throw notFound("Resource not found");
    }

    if (resource.type !== input.resourceType) {
      throw badRequest("Permission resource type does not match resource");
    }

    const permission = await this.storage.permissions.create(input);
    if (!permission) {
      throw internal("Failed to create permission");
    }

    return permission;
  }

  async update(
    id: string,
    input: UpdatePermissionInput,
    context: ServiceContext,
  ): Promise<Permission> {
    const current = await this.requirePermissionAccess(id, context, [
      "owner",
      "admin",
    ]);

    if (input.roleId && input.roleId !== current.permission.roleId) {
      const nextRole = await this.requireManagedRole(input.roleId, context);
      if (nextRole.organizationId !== current.role.organizationId) {
        throw badRequest("Cannot move permission to another organization");
      }
    }

    const permission = await this.storage.permissions.update(id, input);
    if (!permission) {
      throw notFound("Permission not found");
    }

    return permission;
  }

  async delete(id: string, context: ServiceContext): Promise<void> {
    await this.requirePermissionAccess(id, context, ["owner", "admin"]);
    const permission = await this.storage.permissions.delete(id);
    if (!permission) {
      throw notFound("Permission not found");
    }
  }

  async list(
    options: ListOptions<PermissionOrderBy, PermissionListFilter>,
    context: ServiceContext,
  ): Promise<Permission[]> {
    const organizationId = options.filter?.organizationId;
    if (!organizationId) {
      throw badRequest("Organization ID is required");
    }

    if (!permissionOrderByValues.includes(options.orderBy)) {
      throw badRequest("Invalid orderBy");
    }

    await requireOrganizationMembership(
      this.storage,
      organizationId,
      context.userId,
    );

    const roles = await this.storage.roles.listByOrganizationId(organizationId, {
      limit: Number.MAX_SAFE_INTEGER,
      offset: 0,
      orderBy: "createdAt",
      orderDirection: "asc",
      filter: { organizationId },
    });
    const roleIds = roles.map((role: Role) => role.id);

    if (roleIds.length === 0) {
      return [];
    }

    return this.storage.permissions.listByRoleIds(roleIds, {
      ...options,
      filter: { organizationId },
    });
  }

  private async requirePermissionAccess(
    id: string,
    context: ServiceContext,
    allowedRoles?: ("owner" | "admin")[],
  ): Promise<{ permission: Permission; role: Role }> {
    const permission = await this.storage.permissions.findById(id);
    if (!permission) {
      throw notFound("Permission not found");
    }

    const role = await this.storage.roles.findById(permission.roleId);
    if (!role) {
      throw notFound("Role not found");
    }

    await requireOrganizationMembership(
      this.storage,
      role.organizationId,
      context.userId,
      allowedRoles,
    );

    return { permission, role };
  }

  private async requireManagedRole(
    id: string,
    context: ServiceContext,
  ): Promise<Role> {
    const role = await this.storage.roles.findById(id);
    if (!role) {
      throw notFound("Role not found");
    }

    await requireOrganizationMembership(
      this.storage,
      role.organizationId,
      context.userId,
      ["owner", "admin"],
    );

    return role;
  }
}
