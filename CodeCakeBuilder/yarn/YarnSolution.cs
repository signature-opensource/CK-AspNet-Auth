using Cake.Npm;
using CodeCake.Abstractions;
using CSemVer;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml.Linq;

namespace CodeCake
{
    public static class StandardGlobalInfoYarnExtension
    {
        /// <summary>
        /// Adds the <see cref="YarnSolution"/> to the <paramref name="globalInfo"/>
        /// </summary>
        /// <param name="this">This global info.</param>
        /// <param name="solution">The Yarn solution.</param>
        /// <returns>This info.</returns>
        public static StandardGlobalInfo AddYarn( this StandardGlobalInfo globalInfo, YarnSolution solution )
        {
            SVersion minmimalNpmVersionRequired = SVersion.Create( 6, 7, 0 );
            string npmVersion = globalInfo.Cake.NpmGetNpmVersion();
            if( SVersion.Parse( npmVersion ) < minmimalNpmVersionRequired )
            {
                globalInfo.Cake.TerminateWithError( "Outdated npm. Version older than v6.7.0 are known to fail on publish." );
            }
            globalInfo.RegisterSolution( solution );
            return globalInfo;
        }

        /// <summary>
        /// Adds the <see cref="Build.YarnArtifactType"/> for Yarn based on <see cref="YarnSolution.ReadFromYarnSolutionFile"/>
        /// (projects are defined by "CodeCakeBuilder/NPMSolution.xml" file).
        /// </summary>
        /// <param name="this">This global info.</param>
        /// <returns>This info.</returns>
        public static StandardGlobalInfo AddYarn( this StandardGlobalInfo @this )
        {
            return AddYarn( @this, YarnSolution.ReadFromYarnSolutionFile( @this ) );
        }

        /// <summary>
        /// Gets the Yarn solution handled by the single <see cref="Build.YarnArtifactType"/>.
        /// </summary>
        /// <param name="this">This global info.</param>
        /// <returns>The Yarn solution.</returns>
        public static YarnSolution GetYarnSolution( this StandardGlobalInfo @this )
        {
            return @this.Solutions.OfType<YarnSolution>().Single();
        }

    }

    /// <summary>
    /// Encapsulates a set of <see cref="YarnProject"/> that can be <see cref="YarnPublishedProject"/>.
    /// </summary>
    public partial class YarnSolution : YarnProjectContainer, ICIWorkflow
    {
        readonly StandardGlobalInfo _globalInfo;

        /// <summary>
        /// Initiaizes a new <see cref="YarnSolution" />.
        /// </summary>
        /// <param name="projects">Set of projects.</param>
        YarnSolution(
            StandardGlobalInfo globalInfo )
            : base()
        {
            _globalInfo = globalInfo;
        }

        public IEnumerable<YarnAngularWorkspace> AngularWorkspaces => Containers.OfType<YarnAngularWorkspace>();


        public void RunYarnCI()
        {
            foreach( var p in SimpleProjects )
            {
                p.RunYarnCi();
            }

            foreach( var p in AngularWorkspaces )
            {
                p.WorkspaceProject.RunYarnCi();
            }
        }

        public void Clean()
        {
            RunYarnCI();

            foreach( var p in SimpleProjects )
            {
                p.RunClean();
            }

            foreach( var p in AngularWorkspaces )
            {
                p.WorkspaceProject.RunClean();
            }
        }



        /// <summary>
        /// Runs the 'build-debug', 'build-release' or 'build' script on all <see cref="SimpleProjects"/>.
        /// </summary>
        /// <param name="globalInfo">The global information object.</param>
        /// <param name="scriptMustExist">
        /// False to only emit a warning and return false if the script doesn't exist instead of
        /// throwing an exception.
        /// </param>
        public void Build()
        {
            foreach( var p in SimpleProjects )
            {
                p.RunBuild();
            }
            foreach( var p in AngularWorkspaces )
            {
                p.WorkspaceProject.RunBuild();
            }
        }

        /// <summary>
        /// Runs the 'test' script on all <see cref="SimpleProjects"/>.
        /// </summary>
        /// <param name="globalInfo">The global information object.</param>
        /// <param name="globalInfo"></param>
        /// <param name="scriptMustExist">
        /// False to only emit a warning and return false if the script doesn't exist instead of
        /// throwing an exception.
        /// </param>
        public void Test()
        {
            foreach( var p in SimpleProjects )
            {
                p.RunTest();
            }
            foreach( var p in AngularWorkspaces )
            {
                p.WorkspaceProject.RunTest();
            }
        }

        /// <summary>
        /// Generates the .tgz file in the <see cref="StandardGlobalInfo.ReleasesFolder"/>
        /// by calling npm pack for all <see cref="SimplePublishedProjects"/>.
        /// </summary>
        /// <param name="globalInfo">The global information object.</param>
        /// <param name="cleanupPackageJson">
        /// By default, "scripts" and "devDependencies" are removed from the package.json file.
        /// </param>
        /// <param name="packageJsonPreProcessor">Optional package.json pre processor.</param>
        public void RunPack( Action<JObject> packageJsonPreProcessor = null )
        {
            foreach( var p in AllPublishedProjects )
            {
                p.RunPack( packageJsonPreProcessor );
            }
        }

        /// <summary>
        /// Reads the "CodeCakeBuilder/NPMSolution.xml" file that must exist.
        /// </summary>
        /// <param name="version">The version of all published packages.</param>
        /// <returns>The solution object.</returns>
        public static YarnSolution ReadFromYarnSolutionFile( StandardGlobalInfo globalInfo )
        {
            var document = XDocument.Load( "CodeCakeBuilder/NPMSolution.xml" ).Root;
            var solution = new YarnSolution(globalInfo);

            foreach( var item in document.Elements( "AngularWorkspace" ) )
            {
                solution.Add( YarnAngularWorkspace.Create( globalInfo,
                         solution,
                         (string)item.Attribute( "Path" ) ) );
            }
            foreach( var item in document.Elements( "Project" ) )
            {
                solution.Add( YarnPublishedProject.Create(
                        globalInfo,
                        solution,
                        (string)item.Attribute( "Path" ),
                        (string)item.Attribute( "OutputFolder" ) ) );
            }
            return solution;
        }
    }
}
