import { CASConfiguration } from "..";

export const benchmarkMethod = () => {
  return (target: any, propertyKey: string, descriptor: PropertyDescriptor) => {
    const originalMethod = descriptor.value;
    descriptor.value = function (...args: any[]) {
      if (!canSendBenchmark()) {
        return originalMethod.apply(this, args);
      }
      
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

const canSendBenchmark = () => {
  let result = true;
  if (!CASConfiguration.apiKey) {
    result = false;
  }
  return result;
}