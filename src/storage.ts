import type { OrganizationPluginStorage } from "@pure-auth/plugin-organization";
import type {
  ApiKey,
  CreateApiKeyInput,
  CreatePermissionInput,
  CreateResourceInput,
  CreateRoleInput,
  Permission,
  Resource,
  Role,
  UpdatePermissionInput,
  UpdateResourceInput,
  UpdateRoleInput,
} from "./types";

export type RoleOrderBy = "name" | "createdAt" | "updatedAt";
export type PermissionOrderBy = "resourceType" | "createdAt" | "updatedAt";
export type ResourceOrderBy = "type" | "createdAt" | "updatedAt";

export type ListQuery<TOrderBy extends string> = {
  limit: number;
  offset: number;
  orderBy: TOrderBy;
  orderDirection: "asc" | "desc";
  filter?: Record<string, unknown>;
};

export type RoleRepository = {
  findById(id: string): Promise<Role | null>;
  create(input: CreateRoleInput): Promise<Role | null>;
  update(id: string, input: UpdateRoleInput): Promise<Role | null>;
  delete(id: string): Promise<Role | null>;
  listByOrganizationId(
    organizationId: string,
    options: ListQuery<RoleOrderBy>,
  ): Promise<Role[]>;
};

export type PermissionRepository = {
  findById(id: string): Promise<Permission | null>;
  create(input: CreatePermissionInput): Promise<Permission | null>;
  update(id: string, input: UpdatePermissionInput): Promise<Permission | null>;
  delete(id: string): Promise<Permission | null>;
  listByRoleIds(
    roleIds: string[],
    options: ListQuery<PermissionOrderBy>,
  ): Promise<Permission[]>;
  hasRoleResourceAction(input: CreatePermissionInput): Promise<boolean>;
};

export type ResourceRepository = {
  findById(id: string): Promise<Resource | null>;
  findOrganizationResource(organizationId: string): Promise<Resource | null>;
  create(input: CreateResourceInput): Promise<Resource | null>;
  update(id: string, input: UpdateResourceInput): Promise<Resource | null>;
  delete(id: string): Promise<Resource | null>;
  listByOrganizationId(
    organizationId: string,
    options: ListQuery<ResourceOrderBy>,
  ): Promise<Resource[]>;
};

export type ApiKeyRepository = {
  create(input: CreateApiKeyInput & {
    prefix: string;
    secretHash: string;
    createdByUserId: string;
  }): Promise<ApiKey | null>;
  findById(id: string): Promise<ApiKey | null>;
  findByPrefix(prefix: string): Promise<ApiKey | null>;
  listByOrganizationId(
    organizationId: string,
    options: { limit: number; offset: number },
  ): Promise<ApiKey[]>;
  revoke(id: string): Promise<ApiKey | null>;
  rotateSecret(
    id: string,
    input: { prefix: string; secretHash: string },
  ): Promise<ApiKey | null>;
  markUsed(id: string): Promise<void>;
};

export type IamPluginStorage = OrganizationPluginStorage & {
  roles: RoleRepository;
  permissions: PermissionRepository;
  resources: ResourceRepository;
  apiKeys: ApiKeyRepository;
};
