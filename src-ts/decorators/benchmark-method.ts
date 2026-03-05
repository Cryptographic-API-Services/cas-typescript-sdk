import { CASConfiguration } from "..";
import { HttpWrapper } from "../http/http-wrapper";

export function benchmarkMethod(): MethodDecorator {
  return function (
    target: any,
    propertyKey: string | symbol,
    descriptor: PropertyDescriptor
  ): void | PropertyDescriptor {

    if (!descriptor) return;

    const originalMethod = descriptor.value;

    descriptor.value = function (...args: any[]) {

      if (!canSendBenchmark()) {
        return originalMethod.apply(this, args);
      }

      const className = this.constructor.name;
      const startTime = performance.now();

      const result = originalMethod.apply(this, args);

      const endTime = performance.now();
      const timespan = Math.round(endTime - startTime);

      HttpWrapper.sendBenchmark(timespan, className, propertyKey.toString());

      return result;
    };

    return descriptor;
  };
}

const canSendBenchmark = () => {
  return !!CASConfiguration.apiKey;
};