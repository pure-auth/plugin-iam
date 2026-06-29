import {
  badRequest,
  internal,
  notFound,
  type ListOptions,
  type ServiceContext,
} from "@pure-auth/core";
import { requireOrganizationMembership } from "@pure-auth/plugin-organization";
import type { IamPluginStorage, RoleOrderBy } from "@/storage";
import type { CreateRoleInput, Role, UpdateRoleInput } from "@/types";

const roleOrderByValues = ["name", "createdAt", "updatedAt"] as const;

export type RoleListFilter = {
  organizationId?: string;
};

export class RoleService {
  constructor(private readonly storage: IamPluginStorage) {}

  async get(id: string, context: ServiceContext): Promise<Role> {
    const role = await this.storage.roles.findById(id);
    if (!role) {
      throw notFound("Role not found");
    }

    await requireOrganizationMembership(
      this.storage,
      role.organizationId,
      context.userId,
    );
    return role;
  }

  async create(input: CreateRoleInput, context: ServiceContext): Promise<Role> {
    await requireOrganizationMembership(
      this.storage,
      input.organizationId,
      context.userId,
      ["owner", "admin"],
    );

    const role = await this.storage.roles.create(input);
    if (!role) {
      throw internal("Failed to create role");
    }

    return role;
  }

  async update(
    id: string,
    input: UpdateRoleInput,
    context: ServiceContext,
  ): Promise<Role> {
    const role = await this.requireManagedRole(id, context);
    const updated = await this.storage.roles.update(role.id, input);
    if (!updated) {
      throw notFound("Role not found");
    }

    return updated;
  }

  async delete(id: string, context: ServiceContext): Promise<void> {
    const role = await this.requireManagedRole(id, context);
    const deleted = await this.storage.roles.delete(role.id);
    if (!deleted) {
      throw notFound("Role not found");
    }
  }

  async list(
    options: ListOptions<RoleOrderBy, RoleListFilter>,
    context: ServiceContext,
  ): Promise<Role[]> {
    const organizationId = options.filter?.organizationId;
    if (!organizationId) {
      throw badRequest("Organization ID is required");
    }

    if (!roleOrderByValues.includes(options.orderBy)) {
      throw badRequest("Invalid orderBy");
    }

    await requireOrganizationMembership(
      this.storage,
      organizationId,
      context.userId,
    );

    return this.storage.roles.listByOrganizationId(organizationId, {
      ...options,
      filter: { organizationId },
    });
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
