import { useState, useEffect } from "react";
import { useAuth } from "@/hooks/use-auth";
import { useLocation } from "wouter";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/hooks/use-toast";

export default function AuthPage() {
  const { user, loginMutation, registerMutation } = useAuth();
  const [, setLocation] = useLocation();
  const [isLogin, setIsLogin] = useState(true);
  const [loginForm, setLoginForm] = useState({ username: "", password: "" });
  const [registerForm, setRegisterForm] = useState({ username: "", email: "", password: "", confirmPassword: "" });
  const { toast } = useToast();

  // Redirect if already logged in
  useEffect(() => {
    if (user) {
      setLocation("/dashboard");
    }
  }, [user, setLocation]);

  if (user) {
    return null;
  }

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!loginForm.username || !loginForm.password) {
      toast({
        title: "Қателік",
        description: "Барлық өрістерді толтырыңыз",
        variant: "destructive",
      });
      return;
    }

    loginMutation.mutate(loginForm, {
      onSuccess: () => {
        setLocation("/dashboard");
      },
    });
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!registerForm.username || !registerForm.email || !registerForm.password || !registerForm.confirmPassword) {
      toast({
        title: "Қателік",
        description: "Барлық өрістерді толтырыңыз",
        variant: "destructive",
      });
      return;
    }

    if (registerForm.password !== registerForm.confirmPassword) {
      toast({
        title: "Қателік",
        description: "Құпия сөздер сәйкес емес",
        variant: "destructive",
      });
      return;
    }

    if (registerForm.username.length < 5) {
      toast({
        title: "Қателік",
        description: "Пайдаланушы аты кемінде 5 таңбадан тұруы керек",
        variant: "destructive",
      });
      return;
    }

    if (registerForm.password.length < 8) {
      toast({
        title: "Қателік",
        description: "Құпия сөз кемінде 8 таңбадан тұруы керек",
        variant: "destructive",
      });
      return;
    }

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(registerForm.email)) {
      toast({
        title: "Қателік",
        description: "Дұрыс email мекенжайын енгізіңіз",
        variant: "destructive",
      });
      return;
    }

    registerMutation.mutate({
      username: registerForm.username,
      email: registerForm.email,
      password: registerForm.password,
    }, {
      onSuccess: () => {
        setLocation("/dashboard");
      },
    });
  };

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <div className="w-full max-w-4xl grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Hero Section */}
        <div className="flex flex-col justify-center space-y-6 text-left">
          <div className="flex items-center space-x-2">
            <div className="h-10 w-10 rounded-lg bg-primary flex items-center justify-center">
              <i className="fas fa-graduation-cap text-primary-foreground"></i>
            </div>
            <span className="text-2xl font-bold text-foreground">Qadam</span>
          </div>
        </div>

        {/* Auth Forms */}
        <Card className="w-full">
          <CardHeader>
            <div className="flex space-x-1 bg-muted p-1 rounded-md">
              <Button
                variant={isLogin ? "default" : "ghost"}
                size="sm"
                className="flex-1"
                onClick={() => setIsLogin(true)}
                data-testid="button-switch-login"
              >
                Кіру
              </Button>
              <Button
                variant={!isLogin ? "default" : "ghost"}
                size="sm"
                className="flex-1"
                onClick={() => setIsLogin(false)}
                data-testid="button-switch-register"
              >
                Тіркелу
              </Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {isLogin ? (
              <form onSubmit={handleLogin} className="space-y-4" data-testid="form-login">
                <CardTitle>Жүйеге кіру</CardTitle>
                <div className="space-y-2">
                  <Label htmlFor="login-username">Пайдаланушы аты</Label>
                  <Input
                    id="login-username"
                    type="text"
                    placeholder="Пайдаланушы атын енгізіңіз"
                    value={loginForm.username}
                    onChange={(e) => setLoginForm(prev => ({ ...prev, username: e.target.value }))}
                    data-testid="input-login-username"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="login-password">Құпия сөз</Label>
                  <Input
                    id="login-password"
                    type="password"
                    placeholder="Құпия сөзді енгізіңіз"
                    value={loginForm.password}
                    onChange={(e) => setLoginForm(prev => ({ ...prev, password: e.target.value }))}
                    data-testid="input-login-password"
                  />
                </div>
                <Button 
                  type="submit" 
                  className="w-full" 
                  disabled={loginMutation.isPending}
                  data-testid="button-login-submit"
                >
                  {loginMutation.isPending ? "Кіру..." : "Кіру"}
                </Button>
              </form>
            ) : (
              <form onSubmit={handleRegister} className="space-y-4" data-testid="form-register">
                <CardTitle>Аккаунт жасау</CardTitle>
                <div className="space-y-2">
                  <Label htmlFor="register-username">Пайдаланушы аты</Label>
                  <Input
                    id="register-username"
                    type="text"
                    placeholder="Кемінде 5 таңба"
                    value={registerForm.username}
                    onChange={(e) => setRegisterForm(prev => ({ ...prev, username: e.target.value }))}
                    data-testid="input-register-username"
                  />
                  <p className="text-xs text-muted-foreground">
                    Тек әріптер мен сандар, 5-тен 20 таңбаға дейін
                  </p>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="register-email">Email</Label>
                  <Input
                    id="register-email"
                    type="email"
                    placeholder="user@example.com"
                    value={registerForm.email}
                    onChange={(e) => setRegisterForm(prev => ({ ...prev, email: e.target.value }))}
                    data-testid="input-register-email"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="register-password">Құпия сөз</Label>
                  <Input
                    id="register-password"
                    type="password"
                    placeholder="Кемінде 8 таңба"
                    value={registerForm.password}
                    onChange={(e) => setRegisterForm(prev => ({ ...prev, password: e.target.value }))}
                    data-testid="input-register-password"
                  />
                  <p className="text-xs text-muted-foreground">
                    Кемінде 8 таңба, әріптер мен сандарды қамтуы керек
                  </p>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="register-confirm-password">Құпия сөзді растаңыз</Label>
                  <Input
                    id="register-confirm-password"
                    type="password"
                    placeholder="Құпия сөзді қайталаңыз"
                    value={registerForm.confirmPassword}
                    onChange={(e) => setRegisterForm(prev => ({ ...prev, confirmPassword: e.target.value }))}
                    data-testid="input-register-confirm-password"
                  />
                </div>
                <Button 
                  type="submit" 
                  className="w-full" 
                  disabled={registerMutation.isPending}
                  data-testid="button-register-submit"
                >
                  {registerMutation.isPending ? "Тіркелу..." : "Тіркелу"}
                </Button>
              </form>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
