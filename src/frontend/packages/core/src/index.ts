/** ORYVA by Sun — reusable frontend presentation contracts. */
export const ORYVA_PRODUCT_ID = "SUN-001" as const;
export { parseOryvaPrincipal, hasOryvaCapability, getOryvaNavigation } from "./capabilities.js";
export type { OryvaRole, OryvaAccountState, OryvaCapability, OryvaPrincipal } from "./capabilities.js";
