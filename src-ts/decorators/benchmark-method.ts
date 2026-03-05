export function benchmarkMethod() {
  return (target: any, propertyKey: string, descriptor: PropertyDescriptor) => {
    const originalMethod = descriptor.value;
    descriptor.value = function (...args: any[]) {
      const className = this.constructor.name;
      const startTime = performance.now();
      const result = originalMethod.apply(this, args); // Method executes here
      const endTime = performance.now();
      const timespan = Math.round(endTime - startTime);
      // TODO: send the timespan to the cas website

      return result; // Return result after post-execution logic
    };
    return descriptor;
  };
}