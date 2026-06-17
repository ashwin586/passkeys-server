export const calculateStrength = (password: string): number => {
  let size = 0;

  if (/[a-z]/.test(password)) size += 26;
  if (/[A-Z]/.test(password)) size += 26;
  if (/[0-9]/.test(password)) size += 10;
  if (/[^a-zA-Z0-9]/.test(password)) size += 32;

  if (size === 0) return 0;

  const score = password.length * Math.log2(size);
  return Math.min(100, score);
};
