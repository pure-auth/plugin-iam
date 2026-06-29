export type ResourceType = "organization" | "member" | "invitation" | "project";
export type Action = "create" | "read" | "update" | "delete";

export type Role = {
  id: string;
  name: string;
  description?: string | null;
  organizationId: string;
  createdAt?: Date;
  updatedAt?: Date;
};

export type Permission = {
  id: string;
  action: Action;
  resourceId: string;
  resourceType: ResourceType;
  roleId: string;
  createdAt?: Date;
  updatedAt?: Date;
};

export type Resource = {
  id: string;
  type: ResourceType;
  organizationId: string;
  memberId?: string | null;
  invitationId?: string | null;
  createdAt?: Date;
  updatedAt?: Date;
};

export type ApiKey = {
  id: string;
  name: string;
  prefix: string;
  secretHash: string;
  organizationId: string;
  roleId?: string | null;
  createdByUserId: string;
  lastUsedAt?: Date | null;
  expiresAt?: Date | null;
  revokedAt?: Date | null;
  createdAt?: Date;
  updatedAt?: Date;
};

export type PublicApiKey = Omit<ApiKey, "secretHash">;

export type ApiKeyActor = {
  type: "apiKey";
  apiKey: PublicApiKey;
  organizationId: string;
  roleId: string | null;
};

export type CreateRoleInput = {
  name: string;
  description?: string | null;
  organizationId: string;
};

export type UpdateRoleInput = Partial<Pick<Role, "name" | "description">>;

export type CreatePermissionInput = {
  action: Action;
  resourceId: string;
  resourceType: ResourceType;
  roleId: string;
};

export type UpdatePermissionInput = Partial<CreatePermissionInput>;

export type CreateResourceInput = {
  id?: string;
  type: ResourceType;
  organizationId: string;
  memberId?: string | null;
  invitationId?: string | null;
};

export type UpdateResourceInput = Partial<CreateResourceInput>;

export type CreateApiKeyInput = {
  name: string;
  organizationId: string;
  roleId?: string | null;
  expiresAt?: Date | null;
};
