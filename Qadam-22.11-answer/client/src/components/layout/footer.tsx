import { useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/hooks/use-auth";

export default function Footer() {
  const [, setLocation] = useLocation();
  const { user } = useAuth();

  const footerLinks = {
    sections: [
      {
        title: "Разделы",
        links: [
          { label: "Тесты", href: user ? "/dashboard" : "/" },
          { label: "Рейтинг", href: "/ranking" },
          { label: "Профиль", href: "/profile" },
        ]
      },
      {
        title: "Инструменты",
        links: [
          { label: "Калькулятор", href: "#" },
          { label: "Таблица Менделеева", href: "#" },
          { label: "Формулы", href: "#" },
          { label: "Справочники", href: "#" },
        ]
      },
      {
        title: "Поддержка",
        links: [
          { label: "Связаться с нами", href: "#" },
          { label: "FAQ", href: "#" },
          { label: "Правила использования", href: "#" },
          { label: "Конфиденциальность", href: "#" },
        ]
      }
    ],
    socialLinks: [
      { icon: "fab fa-telegram", href: "#", label: "Telegram" },
      { icon: "fab fa-instagram", href: "#", label: "Instagram" },
      { icon: "fab fa-youtube", href: "#", label: "YouTube" },
    ]
  };

  return (
    <footer className="border-t border-border bg-card mt-16">
      <div className="container mx-auto px-4 lg:px-6 py-8">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          {/* Brand Section */}
          <div>
            <div className="flex items-center space-x-2 mb-4">
              <div className="h-6 w-6 rounded-md bg-primary flex items-center justify-center">
                <i className="fas fa-graduation-cap text-primary-foreground text-sm"></i>
              </div>
              <span className="font-bold text-foreground">Qadam</span>
            </div>
            <p className="text-sm text-muted-foreground">
              Современная платформа для подготовки к ЕНТ с интерактивными тестами и подробной аналитикой.
            </p>
          </div>
          
          {/* Link Sections */}
          {footerLinks.sections.map((section, index) => (
            <div key={index}>
              <h4 className="font-semibold text-foreground mb-3">{section.title}</h4>
              <ul className="space-y-2 text-sm">
                {section.links.map((link, linkIndex) => (
                  <li key={linkIndex}>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-auto p-0 text-muted-foreground hover:text-primary transition-colors justify-start"
                      onClick={() => link.href !== "#" && setLocation(link.href)}
                      data-testid={`footer-link-${link.label.toLowerCase().replace(/\s+/g, '-')}`}
                    >
                      {link.label}
                    </Button>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
        
        {/* Footer Bottom */}
        <div className="border-t border-border mt-8 pt-8 flex flex-col md:flex-row items-center justify-between">
          <p className="text-sm text-muted-foreground">
            © 2024 Qadam. Все права защищены.
          </p>
          
          {/* Social Links */}
          <div className="flex items-center space-x-4 mt-4 md:mt-0">
            {footerLinks.socialLinks.map((social, index) => (
              <Button
                key={index}
                variant="ghost"
                size="icon"
                className="h-8 w-8 text-muted-foreground hover:text-primary transition-colors"
                onClick={() => {
                  // In a real app, these would open actual social links
                  console.log(`Opening ${social.label}`);
                }}
                data-testid={`social-link-${social.label.toLowerCase()}`}
              >
                <i className={social.icon}></i>
              </Button>
            ))}
          </div>
        </div>
      </div>
    </footer>
  );
}
