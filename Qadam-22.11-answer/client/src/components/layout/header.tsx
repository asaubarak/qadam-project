import { useAuth } from "@/hooks/use-auth";
import { useTheme } from "@/components/theme-provider";
import { useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { 
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet";
import NotificationBell from "@/components/notification-bell";
import NetworkStatus from "@/components/network-status";

export default function Header() {
  const { user, logoutMutation } = useAuth();
  const { theme, setTheme } = useTheme();
  const [location, setLocation] = useLocation();

  const navigation = [
    { href: user ? "/dashboard" : "/", label: "Басты бет", icon: "fas fa-home" },
    { href: "/profile", label: "Менің профилім", icon: "fas fa-user" },
    { href: "/notifications", label: "Хабарландырулар", icon: "fas fa-bell" },
    { href: "/analytics", label: "Аналитика", icon: "fas fa-chart-line" },
    { href: "/ranking", label: "Рейтинг", icon: "fas fa-trophy" },
  ];

  const handleLogout = () => {
    logoutMutation.mutate(undefined, {
      onSuccess: () => {
        setLocation("/");
      }
    });
  };

  const isActive = (path: string) => {
    if (path === "/") return location === "/";
    return location.startsWith(path);
  };

  const MobileNav = () => (
    <Sheet>
      <SheetTrigger asChild>
        <Button variant="ghost" size="icon" className="md:hidden text-white hover:bg-white/10" data-testid="button-mobile-menu">
          <i className="fas fa-bars"></i>
        </Button>
      </SheetTrigger>
      <SheetContent side="left" className="w-80">
        <div className="flex items-center space-x-2 mb-8">
          <div className="h-8 w-8 rounded-lg bg-primary flex items-center justify-center">
            <i className="fas fa-graduation-cap text-primary-foreground"></i>
          </div>
          <span className="text-xl font-bold text-foreground">Qadam</span>
        </div>
        
        <nav className="space-y-2">
          {navigation.map((item) => (
            <Button
              key={item.href}
              variant={isActive(item.href) ? "default" : "ghost"}
              className="w-full justify-start"
              onClick={() => setLocation(item.href)}
              data-testid={`nav-${item.label.toLowerCase().replace(/\s+/g, '-')}`}
            >
              <i className={`${item.icon} mr-2`}></i>
              {item.label}
            </Button>
          ))}
          
          {/* Дополнительные пункты меню */}
          <div className="border-t pt-2 mt-4">
            <Button
              variant={isActive("/subscription") ? "default" : "ghost"}
              className="w-full justify-start"
              onClick={() => setLocation("/subscription")}
              data-testid="nav-subscription"
            >
              <i className="fas fa-credit-card mr-2"></i>
              Жазылым
            </Button>
            
            {user?.username === "admin" && (
              <Button
                variant={isActive("/admin") ? "default" : "ghost"}
                className="w-full justify-start"
                onClick={() => setLocation("/admin")}
                data-testid="nav-admin"
              >
                <i className="fas fa-cog mr-2"></i>
                Әкімші панелі
              </Button>
            )}
          </div>
        </nav>
        
        <div className="absolute bottom-6 left-6 right-6">
          <Button
            variant="outline"
            className="w-full"
            onClick={() => setTheme(theme === "light" ? "dark" : "light")}
            data-testid="button-theme-toggle-mobile"
          >
            <i className={`fas ${theme === "light" ? "fa-moon" : "fa-sun"} mr-2`}></i>
            {theme === "light" ? "Қараңғы тақырып" : "Ашық тақырып"}
          </Button>
        </div>
      </SheetContent>
    </Sheet>
  );

  return (
    <header className="sticky top-0 z-50 w-full border-b border-blue-700 bg-blue-500 backdrop-blur supports-[backdrop-filter]:bg-blue-500/95 shadow-lg">
      <div className="container mx-auto px-4 lg:px-6">
        <div className="flex h-16 items-center justify-between">
          {/* Logo and Brand */}
          <div className="flex items-center space-x-4">
            <Button
              variant="ghost"
              className="flex items-center space-x-2 hover:bg-transparent p-0"
              onClick={() => setLocation(user ? "/dashboard" : "/")}
              data-testid="brand-logo"
            >
              <div className="h-8 w-8 rounded-lg bg-white/20 flex items-center justify-center">
                <i className="fas fa-graduation-cap text-white"></i>
              </div>
              <span className="text-xl font-bold text-white">Qadam</span>
            </Button>
          </div>
          
          {/* Desktop Navigation */}
          <nav className="hidden md:flex items-center space-x-6">
            {navigation
              .filter(item => !item.adminOnly || user?.username === "admin")
              .map((item) => (
                <Button
                  key={item.href}
                  variant="ghost"
                  className={`text-sm font-medium transition-colors ${
                    isActive(item.href) 
                      ? "text-white bg-white/20" 
                      : "text-blue-50 hover:text-white hover:bg-white/10"
                  }`}
                  onClick={() => setLocation(item.href)}
                  data-testid={`nav-${item.label.toLowerCase().replace(/\s+/g, '-')}`}
                >
                  <i className={`${item.icon} mr-2`}></i>
                  {item.label}
                </Button>
              ))}
          </nav>
          
          {/* User Menu */}
          <div className="flex items-center space-x-4">
            {/* Theme Toggle */}
            <Button 
              variant="ghost" 
              size="icon"
              onClick={() => setTheme(theme === "light" ? "dark" : "light")}
              className="hidden md:inline-flex text-blue-50 hover:text-white hover:bg-white/10"
              data-testid="button-theme-toggle"
            >
              <i className={`fas ${theme === "light" ? "fa-moon" : "fa-sun"}`}></i>
            </Button>
            
            {/* Network Status */}
            <NetworkStatus className="hidden md:flex" />
            
            {/* Notification Bell */}
            {user && <NotificationBell />}
            
            {user ? (
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" className="flex items-center space-x-2 text-white hover:bg-white/10" data-testid="button-user-menu">
                    <Avatar className="h-8 w-8">
                      <AvatarFallback className="bg-white/20 text-white text-sm font-medium">
                        {user.username.charAt(0).toUpperCase()}
                      </AvatarFallback>
                    </Avatar>
                    <span className="hidden md:block font-medium text-white">{user.username}</span>
                    <i className="fas fa-chevron-down text-xs text-blue-50"></i>
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-56">
                  <div className="px-2 py-1.5">
                    <p className="text-sm font-medium text-foreground">{user.username}</p>
                    <p className="text-xs text-muted-foreground">
                      {user.createdAt && new Date(user.createdAt).toLocaleDateString()}
                    </p>
                  </div>
                  <DropdownMenuSeparator />
                  
                  <DropdownMenuItem onClick={() => setLocation("/profile")} data-testid="dropdown-profile">
                    <i className="fas fa-user mr-2"></i>
                    Профиль
                  </DropdownMenuItem>
                  
                  <DropdownMenuItem onClick={() => setLocation("/subscription")} data-testid="dropdown-subscription">
                    <i className="fas fa-credit-card mr-2"></i>
                    Жазылым
                  </DropdownMenuItem>
                  
                  <DropdownMenuItem onClick={() => setLocation("/ranking")} data-testid="dropdown-ranking">
                    <i className="fas fa-trophy mr-2"></i>
                    Рейтинг
                  </DropdownMenuItem>
                  
                  {user.username === "admin" && (
                    <DropdownMenuItem onClick={() => setLocation("/admin")} data-testid="dropdown-admin">
                      <i className="fas fa-cog mr-2"></i>
                      Админка
                    </DropdownMenuItem>
                  )}
                  
                  <DropdownMenuSeparator />
                  
                  <DropdownMenuItem 
                    onClick={handleLogout} 
                    className="text-destructive focus:text-destructive"
                    data-testid="dropdown-logout"
                  >
                    <i className="fas fa-sign-out-alt mr-2"></i>
                    Шығу
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            ) : (
              <Button onClick={() => setLocation("/auth")} className="bg-white text-blue-500 hover:bg-blue-50" data-testid="button-login">
                Кіру
              </Button>
            )}
            
            {/* Mobile Menu Toggle */}
            <MobileNav />
          </div>
        </div>
      </div>
    </header>
  );
}
