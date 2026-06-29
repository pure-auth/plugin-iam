import { createPlugin } from "pure-auth";
import { ApiKeyService, type ApiKeyServiceOptions } from "./services/api-key-service";
import { PermissionService } from "./services/permission-service";
import { ResourceService } from "./services/resource-service";
import { RoleService } from "./services/role-service";
import type { IamPluginStorage } from "./storage";

export type IamPluginOptions = ApiKeyServiceOptions;

export function iamPlugin(options: IamPluginOptions = {}) {
  return createPlugin({
    name: "iam",
    dependencies: ["organization"],
    init(context: { storage: IamPluginStorage }) {
      const apiKeys = new ApiKeyService(context.storage, options);

      return {
        roles: new RoleService(context.storage),
        permissions: new PermissionService(context.storage),
        resources: new ResourceService(context.storage),
        apiKeys,
        actorResolver: apiKeys.actorResolver(),
      };
    },
  });
}

export * from "./access";
export * from "./services/api-key-service";
export * from "./services/permission-service";
export * from "./services/resource-service";
export * from "./services/role-service";
export * from "./storage";
export * from "./types";
