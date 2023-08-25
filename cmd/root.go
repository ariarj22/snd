// Package cmd is the command surface of king cli tool provided by kubuskotak.
// # This manifest was generated by ymir. DO NOT EDIT.
package cmd

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/kubuskotak/asgard/common"
	pkgInf "github.com/kubuskotak/asgard/infrastructure"
	pkgRest "github.com/kubuskotak/asgard/rest"
	"github.com/kubuskotak/asgard/signal"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"

	"github.com/kubuskotak/king/pkg/adapters"
	"github.com/kubuskotak/king/pkg/api/rest"
	"github.com/kubuskotak/king/pkg/infrastructure"
	"github.com/kubuskotak/king/pkg/usecase"
	"github.com/kubuskotak/king/pkg/usecase/pokemon"
	"github.com/kubuskotak/king/pkg/version"
)

type rootOptions struct {
	Path     string
	Filename string
}

// NewRootCmd creates the root command.
func NewRootCmd() *cobra.Command {
	root := &rootOptions{}
	cmds := &cobra.Command{
		Use:   "king",
		Short: "new version ymir implement",
		Long: GenerateTemplate(description,
			map[string]any{
				"BuildTime":  version.GetVersion().BuildDate,
				"Version":    version.GetVersion().VersionNumber(),
				"CommitHash": version.GetVersion().Revision,
			}),
		RunE: root.runServer,
	}
	cmds.PersistentFlags().StringVarP(
		&root.Filename, "config", "c", "config.yaml", "config file name")
	cmds.PersistentFlags().StringVarP(
		&root.Path, "config-path", "d", "./", "config dir path")

	// subcommands
	cmds.AddCommand(newVersionCmd(), newMigrateCmd(), newHotReloadCmd())

	// initialize configuration
	infrastructure.Configuration(
		infrastructure.WithPath(root.Path),
		infrastructure.WithFilename(root.Filename),
	).Initialize()
	pkgInf.InitializeLogger(infrastructure.Envs.App.Environment)

	return cmds
}

func (r *rootOptions) runServer(_ *cobra.Command, _ []string) error {
	fmt.Printf("%s\n", common.Colorize(fmt.Sprintf(logo,
		version.GetVersion().VersionNumber(),
		infrastructure.Envs.Ports.HTTP,
	), common.ColorGreen))
	log.Info().Str("Stage", infrastructure.Envs.App.Environment).Msg("server running...")
	// open-telemetry
	var (
		ctx, cancel   = context.WithCancel(context.Background())
		cleanupTracer pkgInf.TracerReturnFunc
		cleanupMetric pkgInf.MetricReturnFunc
	)
	defer cancel()
	if infrastructure.Envs.Telemetry.CollectorEnable {
		traceExp, traceErr := pkgInf.TraceExporter(ctx,
			infrastructure.Envs.Telemetry.CollectorDebug,
			infrastructure.Envs.Telemetry.CollectorEnable,
			infrastructure.Envs.Telemetry.CollectorGrpcAddr,
			infrastructure.Envs.Server.Timeout)
		if traceErr != nil {
			log.Error().Err(traceErr).Msg("exporter trace is failed")
			return traceErr
		} // tracing exporter
		cleanupTracer = pkgInf.InitTracer(infrastructure.Envs.App.ServiceName, traceExp)
		// initial service for tracing
		var span trace.Span
		tp := otel.Tracer(infrastructure.Envs.App.ServiceName)
		ctx, span = tp.Start(ctx, "root-running")
		defer span.End()

		metricExp, metricErr := pkgInf.MetricExporter(ctx,
			infrastructure.Envs.Telemetry.CollectorDebug,
			infrastructure.Envs.Telemetry.CollectorEnable,
			infrastructure.Envs.Telemetry.CollectorGrpcAddr,
			infrastructure.Envs.Server.Timeout)
		if metricErr != nil {
			log.Error().Err(metricErr).Msg("exporter metric is failed")
			return metricErr
		} // tracing exporter
		cleanupMetric = pkgInf.InitMetric(metricExp)
	}
	/**
	* Initialize Main
	*
	* adaptor.Sync(
	* 	 adapters.WithCrudSQLite(&adapters.CrudSQLite{
	*	 	 File: infrastructure.Envs.CrudSQLite.File}),
	*	 adapters.WithPokemonResty(&adapters.PokemonResty{
	*		 URL: infrastructure.Envs.PokemonResty.URL}),
	* )
	 */
	adaptor := &adapters.Adapter{}
	adaptor.Sync(
		adapters.WithCrudSQLite(&adapters.CrudSQLite{
			File: infrastructure.Envs.CrudSQLite.File}),
		adapters.WithCrudPostgres(&adapters.CrudPostgres{
			User: infrastructure.Envs.CrudPostgres.User,
			Password: infrastructure.Envs.CrudPostgres.Password,
			Host: infrastructure.Envs.CrudPostgres.Host,
			Port: infrastructure.Envs.CrudPostgres.Port,
			Database: infrastructure.Envs.CrudPostgres.Database}),
		adapters.WithCrudMongoDB(&adapters.CrudMongoDB{
			URI: infrastructure.Envs.CrudMongoDB.URI,
			Database: infrastructure.Envs.CrudMongoDB.Database,
			Collection: infrastructure.Envs.CrudMongoDB.Collection,
		}),
		adapters.WithPokemonResty(&adapters.PokemonResty{
			URL: infrastructure.Envs.PokemonResty.URL}),
	) // adapters init
	/**
	* Initialize UseCase
	* pokemonCase, err := usecase.Get[pokemon.T](adaptor)
	* if err != nil {
	*	 return err
	* }
	 */
	pokemonCase, err := usecase.Get[pokemon.T](adaptor)
	if err != nil {
		return err
	}
	var errCh chan error
	/**
	* Initialize HTTP
	*
	* func(c chi.Router) http.Handler {
	* 	rest.NewPokemon(
	*  	  	rest.WithPokemonUseCase(pokemonCase),
	* 	).Register(c)
	* 	c.Mount("/api", c)
	*	return c
	* }
	 */
	h := pkgRest.NewServer(
		pkgRest.WithPort(strconv.Itoa(infrastructure.Envs.Ports.HTTP)),
	)
	h.Handler(rest.Routes().Register(
		func(c chi.Router) http.Handler {
			rest.NewPokemon(
				rest.WithPokemonUseCase(pokemonCase),
			).Register(c)
			rest.NewArticle(
				rest.WithArticleDatabase(adaptor.CrudPostgres),
			).Register(c)
			rest.NewUser(
				rest.WithUserDatabase(adaptor.CrudPostgres),
				rest.WithUserMongoDB(adaptor.CrudMongoDB),
			).Register(c)
			rest.NewApplication(
				rest.WithApplicationDatabase(adaptor.CrudPostgres),
			).Register(c)
			c.Mount("/api", c)
			return c
		},
	)) // http register handler
	if err := h.ListenAndServe(); err != nil {
		return err
	}
	errCh = h.Error()
	// end http
	stopCh := signal.SetupSignalHandler()
	return signal.Graceful(infrastructure.Envs.Server.Timeout, stopCh, errCh, func(ctx context.Context) {
		log.Info().Dur("timeout", infrastructure.Envs.Server.Timeout).Msg("Shutting down HTTP/HTTPS server")
		// open-telemetry
		if infrastructure.Envs.Telemetry.CollectorEnable {
			if err := cleanupTracer(context.Background()); err != nil {
				log.Error().Err(err).Msg("tracer provider server is failed shutdown")
			}
			if err := cleanupMetric(context.Background()); err != nil {
				log.Error().Err(err).Msg("metric provider server is failed shutdown")
			}
		}
		// rest
		if err := h.Quite(context.Background()); err != nil {
			log.Error().Err(err).Msg("http server is failed shutdown")
		}
		h.Stop()
		// adapters
		if err := adaptor.UnSync(); err != nil {
			log.Error().Err(err).Msg("there is failed on UnSync adapter")
		}
	}) // graceful shutdown
}

// Execute is the execute command for root command.
func Execute() error {
	return NewRootCmd().Execute()
}
