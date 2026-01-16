// Utility function to convert a string to its corresponding enum value
// Used for converting database string values to TypeScript enums
// Example: convertEnum(UserRole, 'ADMIN') => UserRole.ADMIN
export const convertEnum = <T extends object>(enumObj: T, value: string): T[keyof T] => {
  return enumObj[value as keyof T];
};
