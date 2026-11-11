// Module shapes the bundlers provide without a package.
declare module "*.yaml" {
  const text: string;
  export default text;
}
declare module "*.wasm" {
  const instance: unknown;
  export default instance;
}
